"""
EPSS Data Fetcher with daily updates
Downloads CSV file directly - more reliable than API
"""

import requests
import pandas as pd
from pathlib import Path
from datetime import datetime
import time
import sqlite3
import gzip
import shutil

class EPSSFetcher:
    """Fetches and processes EPSS scores using CSV download"""
    
    def __init__(self):
        self.csv_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        self.data_dir = Path("data/epss")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.data_file = self.data_dir / "epss_latest.csv"
    
    def validate_csv_format(self, csv_path):
        """
        Pre-flight check: Validate that the CSV file has the expected format.
        Returns True if valid, False otherwise.
        """
        try:
            # Read first few lines to check format
            with open(csv_path, 'r') as f:
                first_line = f.readline().strip()
                second_line = f.readline().strip()
                third_line = f.readline().strip()
            
            # Check first line has metadata format
            if not first_line.startswith('#model_version:'):
                print(f"ERROR: CSV format changed - first line should start with '#model_version:'", flush=True)
                print(f"  Found: {first_line[:50]}...", flush=True)
                return False
            
            # Check second line has column headers
            expected_headers = ['cve', 'epss', 'percentile']
            actual_headers = [h.strip() for h in second_line.split(',')]
            
            if actual_headers != expected_headers:
                print(f"ERROR: CSV format changed - expected headers {expected_headers}", flush=True)
                print(f"  Found headers: {actual_headers}", flush=True)
                return False
            
            # Check third line has valid data (should be a CVE ID)
            if not third_line.startswith('CVE-'):
                print(f"WARNING: Third line does not start with CVE-: {third_line[:30]}", flush=True)
                # Don't fail, just warn
            
            print(f"CSV format validation passed.", flush=True)
            print(f"  Model version: {first_line}", flush=True)
            print(f"  Headers: {actual_headers}", flush=True)
            return True
            
        except Exception as e:
            print(f"ERROR: Failed to validate CSV: {e}", flush=True)
            return False
    
    def sanity_check_epss_data(self, filtered_df, target_year):
        """
        Perform sanity checks on the filtered EPSS data.
        Designed to detect structural/data issues without hardcoded CVE IDs.
        Returns True if data looks valid, False otherwise.
        """
        print("Performing EPSS data sanity checks...", flush=True)
        issues_found = False
        
        # 1. Check DataFrame is not empty
        if filtered_df.empty:
            print(f"  ERROR: No data found for year {target_year}", flush=True)
            return False
        
        record_count = len(filtered_df)
        print(f"  Record count: {record_count:,} CVEs for year {target_year}", flush=True)
        
        # 2. Check required columns exist (MOST IMPORTANT)
        required_columns = ['cve_id', 'epss_score', 'percentile']
        missing_columns = [col for col in required_columns if col not in filtered_df.columns]
        
        if missing_columns:
            print(f"  ERROR: Missing required columns: {missing_columns}", flush=True)
            print(f"  Available columns: {list(filtered_df.columns)}", flush=True)
            return False
        else:
            print(f"  SUCCESS: Required columns present: {required_columns}", flush=True)
        
        # 3. Check CVE ID format (must start with CVE-{year}-)
        sample_cves = filtered_df['cve_id'].head(10).tolist()
        valid_format_count = 0
        for cve in sample_cves:
            if str(cve).startswith(f'CVE-{target_year}-'):
                valid_format_count += 1
        
        if valid_format_count == 0:
            print(f"  ERROR: No CVEs found with expected format 'CVE-{target_year}-XXXX'", flush=True)
            print(f"  Sample CVEs: {sample_cves[:3]}", flush=True)
            return False
        elif valid_format_count < len(sample_cves):
            print(f"  WARNING: {len(sample_cves) - valid_format_count} of {len(sample_cves)} sample CVEs have unexpected format", flush=True)
        else:
            print(f"  SUCCESS: CVE ID format correct (sample: {sample_cves[0]})", flush=True)
        
        # 4. Convert columns to numeric (handle mixed types)
        print(f"  Converting EPSS scores and percentiles to numeric...", flush=True)
        
        # Force conversion to numeric, coerce errors to NaN
        filtered_df['epss_score'] = pd.to_numeric(filtered_df['epss_score'], errors='coerce')
        filtered_df['percentile'] = pd.to_numeric(filtered_df['percentile'], errors='coerce')
        
        # Drop rows with NaN in critical columns
        before_drop = len(filtered_df)
        filtered_df = filtered_df.dropna(subset=['epss_score', 'percentile'])
        after_drop = len(filtered_df)
        
        if after_drop < before_drop:
            print(f"  WARNING: Dropped {before_drop - after_drop} rows with invalid numeric values", flush=True)
        
        # 5. Check EPSS score range (must be between 0 and 1)
        if len(filtered_df) > 0:
            min_score = filtered_df['epss_score'].min()
            max_score = filtered_df['epss_score'].max()
            avg_score = filtered_df['epss_score'].mean()
            
            print(f"  EPSS score range: {min_score:.4f} - {max_score:.4f}", flush=True)
            print(f"  EPSS average: {avg_score:.4f}", flush=True)
            
            if min_score < 0 or max_score > 1:
                print(f"  ERROR: EPSS scores outside valid range (0-1)", flush=True)
                issues_found = True
        else:
            print(f"  ERROR: No valid EPSS scores after cleaning", flush=True)
            return False
        
        # 6. Check percentile range (must be between 0 and 1)
        if len(filtered_df) > 0:
            min_pct = filtered_df['percentile'].min()
            max_pct = filtered_df['percentile'].max()
            print(f"  Percentile range: {min_pct:.4f} - {max_pct:.4f}", flush=True)
            
            if min_pct < 0 or max_pct > 1:
                print(f"  ERROR: Percentiles outside valid range (0-1)", flush=True)
                issues_found = True
        
        # 7. Check for null/empty values in critical columns
        null_cve_ids = filtered_df['cve_id'].isna().sum()
        
        if null_cve_ids > 0:
            print(f"  ERROR: {null_cve_ids} rows have null CVE IDs", flush=True)
            issues_found = True
        
        # 8. Verify data types are now numeric
        if not pd.api.types.is_float_dtype(filtered_df['epss_score']):
            print(f"  ERROR: EPSS score column is not float type after conversion: {filtered_df['epss_score'].dtype}", flush=True)
            issues_found = True
        else:
            print(f"  SUCCESS: EPSS score column is float type", flush=True)
        
        # Final result
        if issues_found:
            print(f"  SANITY CHECK FAILED: One or more issues detected.", flush=True)
            return False
        else:
            print(f"  SANITY CHECK PASSED: All data looks valid.", flush=True)
            return True
    
    def clear_epss_table(self):
        """Clear all existing EPSS records before daily update"""
        try:
            DB_PATH = Path("data/viper.db")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM epss_scores")
            conn.commit()
            conn.close()
            print("Cleared existing EPSS data for fresh daily update", flush=True)
            return True
        except Exception as e:
            print(f"Failed to clear EPSS table: {e}", flush=True)
            return False
    
    def update_cves_table(self, total_records):
        """Update the cves table with EPSS scores in batches with progress"""
        try:
            DB_PATH = Path("data/viper.db")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM cves WHERE cve_id IN (SELECT cve_id FROM epss_scores)")
            total_to_update = cursor.fetchone()[0]
            
            if total_to_update == 0:
                print("No EPSS records to update in CVEs table.", flush=True)
                return True
            
            print(f"Updating CVEs table with EPSS scores ({total_to_update:,} records to update)...", flush=True)
            
            batch_size = 10000
            offset = 0
            updated = 0
            
            while True:
                cursor.execute("""
                    SELECT cve_id FROM epss_scores 
                    ORDER BY cve_id 
                    LIMIT ? OFFSET ?
                """, (batch_size, offset))
                
                batch_ids = [row[0] for row in cursor.fetchall()]
                
                if not batch_ids:
                    break
                
                placeholders = ','.join(['?'] * len(batch_ids))
                cursor.execute(f"""
                    UPDATE cves 
                    SET epss_score = (
                        SELECT epss_score FROM epss_scores 
                        WHERE epss_scores.cve_id = cves.cve_id
                    )
                    WHERE cve_id IN ({placeholders})
                """, batch_ids)
                
                conn.commit()
                
                updated += len(batch_ids)
                percent = (updated / total_to_update) * 100
                print(f"  Progress: {updated:,} / {total_to_update:,} ({percent:.1f}%)", flush=True)
                
                offset += batch_size
            
            conn.close()
            print("CVEs table updated successfully", flush=True)
            
            update_conn = sqlite3.connect(DB_PATH)
            update_cursor = update_conn.cursor()
            update_cursor.execute("""
                INSERT OR REPLACE INTO updates (source, last_run, records_count)
                VALUES ('epss', ?, ?)
            """, (datetime.now().isoformat(), total_records))
            update_conn.commit()
            update_conn.close()
            print(f"Updated EPSS timestamp: {total_records:,} records", flush=True)
            
            return True
        except Exception as e:
            print(f"Failed to update CVEs table: {e}", flush=True)
            return False
    
    def download_and_filter_csv(self, target_year):
        """
        Download EPSS CSV, filter by CVE ID year, then save to database.
        Includes pre-flight validation and sanity checks.
        """
        try:
            from src.utils.database_handler import DatabaseHandler
            
            # Clear existing data first
            self.clear_epss_table()
            
            gz_path = self.data_dir / "epss_temp.csv.gz"
            csv_path = self.data_dir / "epss_temp.csv"
            
            print(f"Downloading EPSS CSV file...", flush=True)
            print(f"URL: {self.csv_url}", flush=True)
            
            # Download with progress
            retry_count = 0
            max_retries = 3
            success = False
            
            while retry_count < max_retries and not success:
                try:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    response = requests.get(self.csv_url, timeout=300, stream=True, headers=headers)
                    
                    if response.status_code == 200:
                        total_size = int(response.headers.get('content-length', 0))
                        downloaded = 0
                        
                        with open(gz_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=65536):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    if total_size > 0:
                                        percent = (downloaded / total_size) * 100
                                        print(f"  Download progress: {percent:.1f}% ({downloaded / 1024 / 1024:.1f} MB / {total_size / 1024 / 1024:.1f} MB)", flush=True)
                        
                        print(f"  Download complete.", flush=True)
                        success = True
                    else:
                        print(f"  HTTP {response.status_code}, retrying...", flush=True)
                        retry_count += 1
                        time.sleep(30)
                except Exception as e:
                    print(f"  Download failed: {e}, retrying ({retry_count + 1}/{max_retries})...", flush=True)
                    retry_count += 1
                    time.sleep(30)
            
            if not success:
                print(f"Failed to download EPSS CSV", flush=True)
                return False
            
            # Extract CSV
            print(f"Extracting CSV...", flush=True)
            with gzip.open(gz_path, 'rb') as f_in:
                with open(csv_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # PRE-FLIGHT CHECK: Validate CSV format
            print(f"Validating CSV format...", flush=True)
            if not self.validate_csv_format(csv_path):
                print(f"CSV format validation failed. The file structure may have changed.", flush=True)
                print(f"Please check the EPSS documentation for format updates.", flush=True)
                return False
            
            # Read CSV - skip the first row (metadata), use second row as headers
            print(f"Reading CSV file...", flush=True)
            df = pd.read_csv(csv_path, skiprows=1, names=['cve_id', 'epss_score', 'percentile'], dtype={'cve_id': str})
            
            print(f"Total records in CSV: {len(df):,}", flush=True)
            
            # Filter by year using CVE ID pattern
            filtered_df = df[df['cve_id'].str.contains(f"CVE-{target_year}-", na=False)].copy()
            print(f"Filtered to {len(filtered_df):,} records for year {target_year}", flush=True)
            
            if filtered_df.empty:
                print(f"No records found for year {target_year}", flush=True)
                return True
            
            # SANITY CHECK: Validate the filtered data (this will also convert types)
            if not self.sanity_check_epss_data(filtered_df, target_year):
                print(f"Sanity checks failed. Aborting database update.", flush=True)
                return False
            
            # Add date column (using .loc to avoid SettingWithCopyWarning)
            filtered_df.loc[:, 'date'] = datetime.now().date().isoformat()
            
            # Save in batches - pass DataFrame, not list of records
            total_saved = 0
            batch_size = 50000
            db = DatabaseHandler()
            
            for i in range(0, len(filtered_df), batch_size):
                batch_df = filtered_df.iloc[i:i+batch_size]
                db.update_epss_scores(batch_df, append_mode=True, update_cves=False)
                total_saved += len(batch_df)
                print(f"  Saved batch {i//batch_size + 1}: {len(batch_df)} records - Total saved: {total_saved:,}", flush=True)
            
            # Close the database connection
            if hasattr(db, 'conn') and db.conn:
                db.conn.close()
            
            print(f"EPSS CSV download complete: {total_saved:,} records for year {target_year} saved", flush=True)
            
            # Update CVEs table once at the end
            self.update_cves_table(total_saved)
            
            # Cleanup temp files
            gz_path.unlink(missing_ok=True)
            csv_path.unlink(missing_ok=True)
            
            return True
            
        except Exception as e:
            print(f"EPSS CSV failed: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return False
    
    def update_database(self) -> bool:
        """Main update method - downloads CSV and filters for current year"""
        current_year = datetime.now().year
        print(f"Running EPSS update for year {current_year}...", flush=True)
        
        if self.download_and_filter_csv(current_year):
            print("EPSS update completed successfully", flush=True)
            return True
        else:
            print("EPSS update failed", flush=True)
            return False
    
    def get_data_age_hours(self) -> float:
        """Return age of EPSS data in hours"""
        if not self.data_file.exists():
            return 999
        file_age = datetime.now() - datetime.fromtimestamp(self.data_file.stat().st_mtime)
        return file_age.total_seconds() / 3600
    
    def flag_for_manual_update(self):
        """Create flag file for dashboard alert"""
        flag_file = self.data_dir / "manual_update_needed.flag"
        flag_file.touch()
        print("Manual update flag created", flush=True)