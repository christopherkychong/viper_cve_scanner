"""
EPSS Data Fetcher Module
Downloads Exploit Prediction Scoring System scores from FIRST.org API.

EPSS scores indicate the probability (0-1) that a CVE will be exploited
in the next 30 days. This module provides multiple fallback methods:
1. API call (preferred, 10,000 records)
2. CSV download (fallback, complete dataset)
3. Cached data (last resort)

The scores are used to prioritize vulnerabilities that are most likely
to be attacked.
"""

import requests
import pandas as pd
import gzip
import shutil
from pathlib import Path
from datetime import datetime

class EPSSFetcher:
    """
    Fetches EPSS scores from FIRST.org and stores them locally.
    
    Provides methods for both API and CSV data sources with automatic
    fallback to ensure reliable data retrieval.
    """
    
    def __init__(self):
        """Initialize API endpoints and local storage paths."""
        self.api_url = "https://api.first.org/data/v1/epss"
        self.csv_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        self.data_dir = Path("data/epss")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.data_file = self.data_dir / "epss_latest.csv"
    
    def update_via_api(self) -> pd.DataFrame:
        """
        Fetch EPSS data via API (preferred method).
        
        Returns:
            DataFrame with columns: cve_id, epss_score, percentile, date
            or None if API call fails
        """
        try:
            response = requests.get(self.api_url, params={'limit': 100000}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                scores = []
                for item in data.get('data', []):
                    scores.append({
                        'cve_id': item.get('cve'),
                        'epss_score': float(item.get('epss', 0)),
                        'percentile': float(item.get('percentile', 0)),
                        'date': datetime.now().date().isoformat()
                    })
                df = pd.DataFrame(scores)
                df.to_csv(self.data_file, index=False)
                print(f"EPSS API update: {len(df)} records")
                return df
            return None
        except Exception as e:
            print(f"EPSS API failed: {e}")
            return None
    
    def update_via_csv(self) -> pd.DataFrame:
        """
        Fallback method: Download and extract compressed CSV file.
        
        The CSV contains all EPSS scores in a single compressed file,
        which is more reliable than paginated API calls.
        
        Returns:
            DataFrame with parsed CSV data or None if download fails
        """
        try:
            gz_path = self.data_dir / "epss_temp.csv.gz"
            csv_path = self.data_dir / "epss_temp.csv"
            
            # Download compressed file
            response = requests.get(self.csv_url, timeout=60, stream=True)
            if response.status_code == 200:
                with open(gz_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Decompress the file
                with gzip.open(gz_path, 'rb') as f_in:
                    with open(csv_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Read and parse CSV
                df = pd.read_csv(csv_path)
                df.columns = ['cve_id', 'epss_score', 'percentile']
                df['date'] = datetime.now().date().isoformat()
                df.to_csv(self.data_file, index=False)
                
                # Clean up temporary files
                gz_path.unlink(missing_ok=True)
                csv_path.unlink(missing_ok=True)
                
                print(f"EPSS CSV update: {len(df)} records")
                return df
            return None
        except Exception as e:
            print(f"EPSS CSV failed: {e}")
            return None
    
    def use_cached_data(self) -> pd.DataFrame:
        """
        Last resort: Use most recent cached data if available.
        
        Returns:
            DataFrame from cached CSV file or None if no cache exists
        """
        if self.data_file.exists():
            df = pd.read_csv(self.data_file)
            file_age = datetime.now() - datetime.fromtimestamp(self.data_file.stat().st_mtime)
            print(f"Using cached EPSS data ({file_age.days} days old) - {len(df)} records")
            return df
        return None
    
    def update_database(self) -> bool:
        """
        Main update method with fallbacks - saves to SQLite database.
        
        Tries multiple data sources in order:
        1. API call (fastest, but may be rate-limited)
        2. CSV download (complete dataset, reliable)
        3. Cached data (last resort)
        
        Returns:
            True if data was successfully saved, False otherwise
        """
        print("Running EPSS update...")
        
        # Try to get data from various sources
        df = self.update_via_api()
        if df is None:
            df = self.update_via_csv()
        if df is None:
            df = self.use_cached_data()
        
        if df is not None and not df.empty:
            # Save to SQLite database
            try:
                from src.utils.database_handler import DatabaseHandler
                db = DatabaseHandler()
                db.update_epss_scores(df)
                print(f"Successfully saved {len(df)} EPSS records to database")
                return True
            except Exception as e:
                print(f"Failed to save to database: {e}")
                return False
        else:
            print("No EPSS data available from any source")
            return False
    
    def get_data_age_hours(self) -> float:
        """
        Return age of EPSS data in hours for dashboard alerts.
        
        Returns:
            Age in hours, or 999 if no data exists
        """
        if not self.data_file.exists():
            return 999
        file_age = datetime.now() - datetime.fromtimestamp(self.data_file.stat().st_mtime)
        return file_age.total_seconds() / 3600
    
    def flag_for_manual_update(self):
        """
        Create flag file for dashboard alert when data is stale.
        """
        flag_file = self.data_dir / "manual_update_needed.flag"
        flag_file.touch()
        print("Manual update flag created")