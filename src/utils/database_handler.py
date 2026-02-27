"""
Database Handler for VIPER
Manages all SQLite database operations including table creation, data insertion, and queries.

This module handles:
- Creating and initializing database tables
- Storing CVE data from NVD
- Managing EPSS scores and KEV status
- Retrieving CVEs with priority calculations
- Tracking update history for each data source
"""

import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

class DatabaseHandler:
    """
    Provides methods to interact with the SQLite database.
    
    Handles connections, table creation, and data operations for:
    - CVEs (vulnerability descriptions and metadata)
    - EPSS scores (exploitation probability)
    - Update tracking (last run timestamps)
    """
    
    def __init__(self, db_path=None):
        """
        Initialize the database handler and ensure tables exist.
        
        Args:
            db_path: Optional custom path to the database file
                    Defaults to 'data/viper.db'
        """
        if db_path is None:
            self.db_path = Path("data/viper.db")
        else:
            self.db_path = Path(db_path)
        
        # Create data directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """
        Create database tables if they don't already exist.
        
        Tables created:
        - cves: Main vulnerability information
        - epss_scores: Daily EPSS scores for trend analysis
        - updates: Track last run times for each data source
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main CVEs table - stores all vulnerability information
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,              -- CVE identifier (e.g., CVE-2024-1234)
                description TEXT,                  -- Full vulnerability description from NVD
                published_date TEXT,                -- Date CVE was published
                cvss_score REAL,                    -- CVSS severity score (0-10)
                severity TEXT,                       -- Text severity (LOW, MEDIUM, HIGH, CRITICAL)
                epss_score REAL DEFAULT 0,          -- Exploitation probability (0-1)
                in_kev INTEGER DEFAULT 0,           -- Whether in CISA's Known Exploited Vulnerabilities
                risk_score REAL,                     -- Combined risk score (for future use)
                last_updated TEXT                    -- Timestamp of last update
            )
        ''')
        
        # EPSS scores table - stores daily scores for trend analysis
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,                    -- Exploitation probability score (0-1)
                percentile REAL,                     -- Percentile rank among all CVEs
                date TEXT                            -- Date when this score was recorded
            )
        ''')
        
        # Updates table - tracks when each data source was last refreshed
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS updates (
                source TEXT PRIMARY KEY,            -- Data source name (nvd, epss, kev)
                last_run TEXT,                       -- Timestamp of last successful update
                records_count INTEGER                 -- Number of records processed
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def update_cve_data(self, cve_list):
        """
        Insert or update CVEs from NVD into the database.
        
        Args:
            cve_list: List of CVE dictionaries with fields:
                     cve_id, description, published_date, cvss_score, severity
                     
        Returns:
            Number of CVEs successfully processed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        count = 0
        
        for cve in cve_list:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, published_date, cvss_score, severity, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    cve['cve_id'],
                    cve['description'],
                    cve.get('published_date', now),
                    cve['cvss_score'],
                    cve.get('severity', 'UNKNOWN'),
                    now
                ))
                count += 1
            except Exception as e:
                print(f"Error inserting {cve.get('cve_id')}: {e}")
        
        # Record this update in the updates table
        cursor.execute('''
            INSERT OR REPLACE INTO updates (source, last_run, records_count)
            VALUES ('nvd', ?, ?)
        ''', (now, count))
        
        conn.commit()
        conn.close()
        return count
    
    def update_epss_scores(self, df):
        """
        Update EPSS scores in the database.
        
        This method:
        1. Replaces the entire epss_scores table with new data
        2. Updates matching records in the cves table with new EPSS scores
        3. Records the update timestamp
        
        Args:
            df: DataFrame with columns cve_id, epss_score, percentile, date
        """
        conn = sqlite3.connect(self.db_path)
        
        # Replace the epss_scores table with new data
        df.to_sql('epss_scores', conn, if_exists='replace', index=False)
        
        # Update the main cves table with new EPSS scores
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE cves 
            SET epss_score = (
                SELECT epss_score FROM epss_scores 
                WHERE epss_scores.cve_id = cves.cve_id
            )
            WHERE cve_id IN (SELECT cve_id FROM epss_scores)
        ''')
        
        # Record this update
        now = datetime.now().isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO updates (source, last_run, records_count)
            VALUES ('epss', ?, ?)
        ''', (now, len(df)))
        
        conn.commit()
        conn.close()
        print(f"EPSS database updated with {len(df)} records")
    
    def update_kev_status(self, kev_set):
        """
        Mark CVEs that are in the CISA KEV catalog.
        
        Args:
            kev_set: Set of CVE IDs that are actively exploited
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Reset all CVEs to not exploited
        cursor.execute("UPDATE cves SET in_kev = 0")
        
        # Mark matching CVEs as exploited
        if kev_set:
            placeholders = ','.join(['?'] * len(kev_set))
            query = f"UPDATE cves SET in_kev = 1 WHERE cve_id IN ({placeholders})"
            cursor.execute(query, list(kev_set))
        
        # Record this update
        now = datetime.now().isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO updates (source, last_run, records_count)
            VALUES ('kev', ?, ?)
        ''', (now, len(kev_set)))
        
        conn.commit()
        conn.close()
        print(f"KEV status updated: {len(kev_set)} CVEs marked as exploited")
    
    def get_all_cves(self, limit=1000):
        """
        Retrieve CVEs from the database with EPSS scores and calculate priorities.
        
        Priority levels:
        - 🔴 PRIORITY 1+ (IMMEDIATE): Confirmed exploited (in KEV)
        - 🟠 PRIORITY 1 (This week): EPSS > 0.2 and CVSS > 7.0
        - 🟡 PRIORITY 2 (Schedule): CVSS > 7.0
        - 🟢 PRIORITY 3 (Monitor): EPSS > 0.2
        - ⚪ PRIORITY 4 (Deprioritize): Low severity and low probability
        
        Args:
            limit: Maximum number of CVEs to return
            
        Returns:
            List of CVE dictionaries with priority added
        """
        conn = sqlite3.connect(self.db_path)
        
        query = f"""
            SELECT 
                c.cve_id,
                c.description,
                c.cvss_score,
                c.severity,
                COALESCE(e.epss_score, 0) as epss_score,
                e.percentile,
                c.in_kev,
                c.published_date,
                c.last_updated
            FROM cves c
            LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
            ORDER BY e.epss_score DESC, c.cvss_score DESC
            LIMIT {limit}
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        # Return sample data if database is empty
        if df.empty:
            return self.get_sample_cves()
        
        cves = []
        for _, row in df.iterrows():
            cve = row.to_dict()
            
            # Calculate priority based on KEV status, EPSS score, and CVSS score
            if cve['in_kev']:
                priority = "🔴 PRIORITY 1+ (IMMEDIATE)"
            elif cve['epss_score'] > 0.2 and cve['cvss_score'] > 7.0:
                priority = "🟠 PRIORITY 1 (This week)"
            elif cve['cvss_score'] > 7.0:
                priority = "🟡 PRIORITY 2 (Schedule)"
            elif cve['epss_score'] > 0.2:
                priority = "🟢 PRIORITY 3 (Monitor)"
            else:
                priority = "⚪ PRIORITY 4 (Deprioritize)"
            
            cve['priority'] = priority
            cves.append(cve)
        
        return cves
    
    def get_sample_cves(self):
        """
        Provide sample CVEs when database is empty.
        
        Returns:
            List of sample CVE dictionaries for testing/development
        """
        return [
            {
                'cve_id': 'SAMPLE-2025-001',
                'description': 'Buffer overflow in Siemens PLC allowing remote code execution',
                'cvss_score': 9.8,
                'epss_score': 0.89,
                'in_kev': True,
                'priority': '🔴 PRIORITY 1+ (IMMEDIATE)'
            },
            {
                'cve_id': 'SAMPLE-2025-002',
                'description': 'Authentication bypass in Philips MRI software exposing patient data',
                'cvss_score': 8.5,
                'epss_score': 0.45,
                'in_kev': False,
                'priority': '🟠 PRIORITY 1 (This week)'
            }
        ]
    
    def get_last_update(self, source):
        """
        Get the last update timestamp and record count for a data source.
        
        Args:
            source: Data source name ('nvd', 'epss', or 'kev')
            
        Returns:
            Tuple of (last_run, records_count) or None if no updates found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT last_run, records_count FROM updates WHERE source = ?",
            (source,)
        )
        result = cursor.fetchone()
        conn.close()
        return result