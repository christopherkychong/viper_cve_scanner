"""
NVD Data Fetcher
Fetches real CVE descriptions and CVSS scores using direct JSON feed download
More reliable than API - single download per year
"""

import requests
import time
from datetime import datetime, timedelta
from pathlib import Path
import json
import sqlite3
import gzip
import shutil

class NVDFetcher:
    """Fetches CVE data from NVD using JSON feed downloads"""
    
    def __init__(self, api_key=None):
        # =========================================================
        # PUT YOUR NVD API KEY HERE
        # Get your free API key from: https://nvd.nist.gov/developers/request-an-api-key
        # =========================================================
        self.api_key = "PUT_API_KEY_HERE"  # <-- REPLACE THIS WITH YOUR ACTUAL API KEY
        # =========================================================
        
        self.data_dir = Path("data/nvd")
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def validate_json_format(self, json_path):
        """
        Pre-flight check: Validate that the JSON file has the expected structure.
        Returns True if valid, False otherwise.
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check for expected top-level keys
            if 'vulnerabilities' not in data:
                print(f"ERROR: JSON format changed - 'vulnerabilities' key not found", flush=True)
                print(f"  Found keys: {list(data.keys())}", flush=True)
                return False
            
            if not isinstance(data['vulnerabilities'], list):
                print(f"ERROR: JSON format changed - 'vulnerabilities' is not a list", flush=True)
                return False
            
            # Check a sample CVE has expected structure
            if len(data['vulnerabilities']) > 0:
                sample = data['vulnerabilities'][0]
                if 'cve' not in sample:
                    print(f"ERROR: JSON format changed - 'cve' key not found in vulnerability", flush=True)
                    print(f"  Found keys: {list(sample.keys())}", flush=True)
                    return False
                
                if 'id' not in sample.get('cve', {}):
                    print(f"ERROR: JSON format changed - 'id' key not found in cve object", flush=True)
                    return False
            
            print(f"JSON format validation passed.", flush=True)
            return True
            
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON file: {e}", flush=True)
            return False
        except Exception as e:
            print(f"ERROR: Failed to validate JSON: {e}", flush=True)
            return False
    
    def sanity_check_nvd_data(self, cve_list, target_year):
        """
        Perform sanity checks on parsed NVD CVE data.
        Returns True if data looks valid, False otherwise.
        """
        print("Performing NVD data sanity checks...", flush=True)
        issues_found = False
        
        if not cve_list:
            print(f"  ERROR: No CVE data to check", flush=True)
            return False
        
        print(f"  Record count: {len(cve_list):,} CVEs for year {target_year}", flush=True)
        
        # 1. Check sample of CVEs for required fields
        sample_size = min(10, len(cve_list))
        sample = cve_list[:sample_size]
        
        required_fields = ['cve_id', 'description', 'cvss_score']
        for field in required_fields:
            missing_in_sample = [cve['cve_id'] for cve in sample if field not in cve or not cve[field]]
            if missing_in_sample:
                print(f"  WARNING: {len(missing_in_sample)} CVEs missing '{field}' field", flush=True)
        
        # 2. Check CVE ID format
        valid_ids = 0
        for cve in sample:
            if cve.get('cve_id', '').startswith(f'CVE-{target_year}-'):
                valid_ids += 1
        
        if valid_ids == 0:
            print(f"  ERROR: No CVEs found with expected format 'CVE-{target_year}-XXXX'", flush=True)
            return False
        else:
            print(f"  SUCCESS: CVE ID format correct", flush=True)
        
        # 3. Check CVSS score range
        cvss_scores = [cve.get('cvss_score', 0) for cve in cve_list if cve.get('cvss_score') is not None]
        if cvss_scores:
            min_cvss = min(cvss_scores)
            max_cvss = max(cvss_scores)
            print(f"  CVSS score range: {min_cvss:.1f} - {max_cvss:.1f}", flush=True)
            
            if min_cvss < 0 or max_cvss > 10:
                print(f"  ERROR: CVSS scores outside valid range (0-10)", flush=True)
                issues_found = True
        
        # 4. Check for empty descriptions
        empty_descriptions = sum(1 for cve in cve_list if not cve.get('description'))
        if empty_descriptions > 0:
            print(f"  WARNING: {empty_descriptions} CVEs have empty descriptions", flush=True)
        
        if issues_found:
            print(f"  SANITY CHECK FAILED: One or more issues detected.", flush=True)
            return False
        else:
            print(f"  SANITY CHECK PASSED: All data looks valid.", flush=True)
            return True
    
    def fetch_cves_by_csv(self, year, db_handler):
        """
        Download NVD JSON feed for a specific year and filter by CVE ID.
        Includes pre-flight validation and sanity checks.
        """
        try:
            # Construct URL for the current year's feed
            csv_url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
            
            print(f"Downloading NVD JSON feed for year {year}...", flush=True)
            print(f"URL: {csv_url}", flush=True)
            
            gz_path = self.data_dir / f"nvdcve-2.0-{year}.json.gz"
            json_path = self.data_dir / f"nvdcve-2.0-{year}.json"
            
            # Check if file already exists locally
            if gz_path.exists():
                print(f"File already exists locally: {gz_path}", flush=True)
                print(f"Using existing file. Delete it if you want to re-download.", flush=True)
            else:
                # Prepare headers with API key
                headers = {}
                if self.api_key and self.api_key != "PUT_API_KEY_HERE":
                    headers['apiKey'] = self.api_key
                    print(f"Using API key for authentication (higher rate limits)", flush=True)
                else:
                    print(f"WARNING: No valid API key provided. Rate limits will be very low.", flush=True)
                    print(f"Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key", flush=True)
                
                # Download with progress
                retry_count = 0
                max_retries = 3
                success = False
                
                while retry_count < max_retries and not success:
                    try:
                        response = requests.get(csv_url, timeout=300, stream=True, headers=headers)
                        
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
                        elif response.status_code == 503:
                            print(f"  Server busy (503). Waiting 60 seconds before retry...", flush=True)
                            retry_count += 1
                            time.sleep(60 * (retry_count + 1))
                        elif response.status_code == 403:
                            print(f"  API key invalid or rate limit exceeded. Status: {response.status_code}", flush=True)
                            print(f"  Please check your API key or wait a few minutes.", flush=True)
                            retry_count += 1
                            time.sleep(60 * (retry_count + 1))
                        else:
                            print(f"  HTTP {response.status_code}, retrying...", flush=True)
                            retry_count += 1
                            time.sleep(30 * (retry_count + 1))
                            
                    except Exception as e:
                        print(f"  Download failed: {e}, retrying ({retry_count + 1}/{max_retries})...", flush=True)
                        retry_count += 1
                        time.sleep(30 * (retry_count + 1))
                
                if not success:
                    print(f"Failed to download NVD feed for year {year}", flush=True)
                    return False
            
            # Extract JSON
            print(f"Extracting JSON...", flush=True)
            with gzip.open(gz_path, 'rb') as f_in:
                with open(json_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # PRE-FLIGHT CHECK: Validate JSON format
            print(f"Validating JSON format...", flush=True)
            if not self.validate_json_format(json_path):
                print(f"JSON format validation failed. The file structure may have changed.", flush=True)
                print(f"Please check the NVD documentation for format updates.", flush=True)
                return False
            
            # Parse JSON
            print(f"Parsing JSON...", flush=True)
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            cve_items = data.get('vulnerabilities', [])
            print(f"Found {len(cve_items):,} CVEs in the feed", flush=True)
            
            # Parse and filter for current year
            all_parsed_cves = []
            for i, cve_item in enumerate(cve_items):
                parsed_cve = self.parse_cve(cve_item)
                if parsed_cve and parsed_cve['description']:
                    # Double-check year in CVE ID
                    if f"CVE-{year}-" in parsed_cve['cve_id']:
                        all_parsed_cves.append(parsed_cve)
                
                # Show progress every 10,000 CVEs
                if (i + 1) % 10000 == 0:
                    percent = (i + 1) / len(cve_items) * 100
                    print(f"  Processing progress: {i + 1:,}/{len(cve_items):,} ({percent:.1f}%)", flush=True)
            
            print(f"Filtered to {len(all_parsed_cves):,} CVEs for year {year}", flush=True)
            
            # SANITY CHECK: Validate the parsed data
            if not self.sanity_check_nvd_data(all_parsed_cves, year):
                print(f"Sanity checks failed. Aborting database update.", flush=True)
                return False
            
            # Save to database
            if all_parsed_cves:
                print(f"\nSaving {len(all_parsed_cves):,} CVEs to database...", flush=True)
                self.save_cves_to_database_with_progress(db_handler, all_parsed_cves)
            else:
                print(f"No CVEs found for year {year}", flush=True)
            
            # Cleanup temp files
            gz_path.unlink(missing_ok=True)
            json_path.unlink(missing_ok=True)
            
            # Update updates table
            now = datetime.now().isoformat()
            conn = sqlite3.connect('data/viper.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO updates (source, last_run, records_count)
                VALUES ('nvd', ?, ?)
            """, (now, len(all_parsed_cves)))
            conn.commit()
            conn.close()
            
            print(f"\n[OK] Completed: Saved {len(all_parsed_cves):,} CVEs for year {year}", flush=True)
            return True
            
        except Exception as e:
            print(f"NVD CSV fetch failed: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return False
    
    def fetch_cves_by_current_year(self, db_handler):
        """Fetch CVEs for the current year using CSV download."""
        current_year = datetime.now().year
        return self.fetch_cves_by_csv(current_year, db_handler)
    
    def save_cves_to_database_with_progress(self, db_handler, cve_list, batch_size=5000):
        """Save CVEs to database in batches with progress percentage"""
        total = len(cve_list)
        if total == 0:
            print("No CVEs to save.", flush=True)
            return 0
        
        print(f"Saving {total:,} CVEs to database in batches of {batch_size:,}...", flush=True)
        
        saved = 0
        for i in range(0, total, batch_size):
            batch = cve_list[i:i+batch_size]
            db_handler.update_cve_data(batch)
            saved += len(batch)
            percent = (saved / total) * 100
            print(f"  Progress: {saved:,} / {total:,} ({percent:.1f}%)", flush=True)
        
        return saved
    
    def fetch_recent_cves(self, days_back=30, limit=None):
        """Fetch CVEs from the last X days using direct API calls."""
        print(f"Fetching CVEs from last {days_back} days...", flush=True)
        
        end = datetime.now()
        start = end - timedelta(days=days_back)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        all_cves = []
        results_per_page = 2000
        start_index = 0
        
        headers = {}
        if self.api_key and self.api_key != "PUT_API_KEY_HERE":
            headers['apiKey'] = self.api_key
        
        try:
            while True:
                params = {
                    'pubStartDate': start_str,
                    'pubEndDate': end_str,
                    'resultsPerPage': results_per_page,
                    'startIndex': start_index
                }
                
                response = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'vulnerabilities' in data:
                        page_cves = data['vulnerabilities']
                        all_cves.extend(page_cves)
                        
                        print(f"  Fetched {len(page_cves)} CVEs (offset {start_index}) - Total so far: {len(all_cves)}", flush=True)
                        
                        total_results = data.get('totalResults', 0)
                        if start_index + len(page_cves) >= total_results:
                            break
                            
                        start_index += len(page_cves)
                        
                        if limit and len(all_cves) >= limit:
                            all_cves = all_cves[:limit]
                            break
                    else:
                        break
                elif response.status_code == 403:
                    print("API key required or invalid. Please check your API key.", flush=True)
                    return []
                else:
                    print(f"API error: {response.status_code}", flush=True)
                    break
                
                time.sleep(6)
            
            print(f"Fetched {len(all_cves)} CVEs from NVD", flush=True)
            return all_cves
            
        except Exception as e:
            print(f"NVD fetch failed: {e}", flush=True)
            return []
    
    def parse_cve(self, cve_data):
        """Extract relevant fields from NVD JSON feed response"""
        try:
            # Handle feed format
            if 'cve' in cve_data:
                cve = cve_data.get('cve', {})
            else:
                cve = cve_data
            
            cve_id = cve.get('id', '')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')
            
            # Get CVSS score
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            metrics = cve.get('metrics', {})
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            published = cve.get('published', '')
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published_date': published,
                'last_modified': cve.get('lastModified', '')
            }
            
        except Exception as e:
            print(f"Error parsing CVE: {e}", flush=True)
            return None


if __name__ == "__main__":
    fetcher = NVDFetcher()
    current_year = datetime.now().year
    
    # Create a mock DB handler for testing
    class MockDB:
        def update_cve_data(self, cves):
            print(f"Would save {len(cves)} CVEs")
    
    print(f"Testing NVD CSV download for year {current_year}...")
    fetcher.fetch_cves_by_csv(current_year, MockDB())