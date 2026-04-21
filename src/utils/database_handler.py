"""
Database Handler for VIPER
Reads from epss_scores table with real data and sector assignment
"""

import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

class DatabaseHandler:
    """Handles all database operations for VIPER"""
    
    def __init__(self, db_path=None):
        if db_path is None:
            self.db_path = Path("data/viper.db")
        else:
            self.db_path = Path(db_path)
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                description TEXT,
                published_date TEXT,
                cvss_score REAL,
                severity TEXT,
                epss_score REAL DEFAULT 0,
                in_kev INTEGER DEFAULT 0,
                risk_score REAL,
                last_updated TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,
                percentile REAL,
                date TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS updates (
                source TEXT PRIMARY KEY,
                last_run TEXT,
                records_count INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def update_cve_data(self, cve_list, batch_size=5000):
        """Insert or update CVEs from NVD in batches for speed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        count = 0
        
        # Process in batches
        for i in range(0, len(cve_list), batch_size):
            batch = cve_list[i:i+batch_size]
            
            # Use executemany for batch INSERT
            data = []
            for cve in batch:
                data.append((
                    cve['cve_id'],
                    cve['description'],
                    cve.get('published_date', now),
                    cve['cvss_score'],
                    cve.get('severity', 'UNKNOWN'),
                    now
                ))
            
            cursor.executemany('''
                INSERT OR REPLACE INTO cves 
                (cve_id, description, published_date, cvss_score, severity, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', data)
            
            conn.commit()
            count += len(batch)
        
        cursor.execute('''
            INSERT OR REPLACE INTO updates (source, last_run, records_count)
            VALUES ('nvd', ?, ?)
        ''', (now, count))
        
        conn.commit()
        conn.close()
        return count
    
    def update_epss_scores(self, df, append_mode=False, update_cves=True):
        """
        Update EPSS scores in database.
        If append_mode=True, appends to existing table (for batch updates).
        If append_mode=False, replaces entire table (for full updates).
        If update_cves=False, skips updating the cves table (for batch speed).
        """
        conn = sqlite3.connect(self.db_path)
        
        if append_mode:
            # Append to existing table (for batch updates)
            df.to_sql('epss_scores', conn, if_exists='append', index=False)
            print(f"EPSS batch appended with {len(df)} records")
        else:
            # Replace entire table (for full updates)
            df.to_sql('epss_scores', conn, if_exists='replace', index=False)
            print(f"EPSS table replaced with {len(df)} records")
        
        # Only update cves table if requested (skip during batches for speed)
        if update_cves:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE cves 
                SET epss_score = (
                    SELECT epss_score FROM epss_scores 
                    WHERE epss_scores.cve_id = cves.cve_id
                )
                WHERE cve_id IN (SELECT cve_id FROM epss_scores)
            ''')
            
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT OR REPLACE INTO updates (source, last_run, records_count)
                VALUES ('epss', ?, ?)
            ''', (now, len(df)))
            print(f"EPSS database fully updated with {len(df)} records")
        
        conn.commit()
        conn.close()
    
    def clear_epss_table(self):
        """Clear all EPSS records before daily update"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM epss_scores")
        conn.commit()
        conn.close()
        print("Cleared EPSS table for fresh update")
    
    def update_kev_status(self, kev_set):
        """Mark CVEs that are in CISA KEV"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE cves SET in_kev = 0")
        
        if kev_set:
            placeholders = ','.join(['?'] * len(kev_set))
            query = f"UPDATE cves SET in_kev = 1 WHERE cve_id IN ({placeholders})"
            cursor.execute(query, list(kev_set))
        
        now = datetime.now().isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO updates (source, last_run, records_count)
            VALUES ('kev', ?, ?)
        ''', (now, len(kev_set)))
        
        conn.commit()
        conn.close()
        print(f"KEV status updated: {len(kev_set)} CVEs marked as exploited")
    
    def get_all_cves(self, limit=1000):
        """Get CVEs from database with EPSS scores and priorities"""
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
        
        if df.empty:
            return self.get_sample_cves()
        
        cves = []
        for _, row in df.iterrows():
            cve = row.to_dict()
            
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
        """Return sample CVEs only if database is empty"""
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
        """Get last update time for a source"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT last_run, records_count FROM updates WHERE source = ?",
            (source,)
        )
        result = cursor.fetchone()
        conn.close()
        return result