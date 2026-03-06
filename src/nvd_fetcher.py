
"""
NVD Data Fetcher Module
Downloads CVE information from the National Vulnerability Database API.

This module provides:
- Paginated fetching of recent CVEs
- Rate limiting to respect API limits
- Parsing of CVE descriptions and CVSS scores
- Error handling for API failures

The NVD is the primary source for CVE descriptions and severity scores,
which are essential for understanding vulnerabilities and applying
sector-specific keyword filters.
"""

import requests
import time
from datetime import datetime, timedelta
from pathlib import Path

class NVDFetcher:
    """
    Fetches CVE data from the NVD API with proper rate limiting.
    
    Handles pagination to retrieve large numbers of CVEs and respects
    API rate limits to avoid being blocked. Provides methods to fetch
    recent CVEs and parse them into a consistent format.
    """
    
    def __init__(self, api_key=None):
        """
        Initialize the NVD fetcher with rate limiting configuration.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
                    Without key: 5 requests per 30 seconds (6s delay)
                    With key: 50 requests per 30 seconds (2s delay)
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.data_dir = Path("data/nvd")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure rate limiting based on API key presence
        if api_key:
            self.delay = 2  # 50 requests per 30 seconds
        else:
            self.delay = 6  # 5 requests per 30 seconds
    
    def fetch_recent_cves(self, days_back=30, limit=1000):
        """
        Download CVEs published in the last specified number of days.
        
        Handles pagination automatically and respects rate limits.
        
        Args:
            days_back: Number of days to look back for published CVEs
            limit: Maximum number of CVEs to return
            
        Returns:
            List of raw CVE objects from the NVD API
        """
        print(f"Fetching CVEs from last {days_back} days...")
        
        # Calculate date range for API query
        end = datetime.now()
        start = end - timedelta(days=days_back)
        
        # Format dates for API (required format)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        all_cves = []
        results_per_page = 2000  # NVD maximum per page
        start_index = 0
        
        # Set up headers for API key if provided
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            # Continue fetching until we reach the limit or run out of results
            while len(all_cves) < limit:
                params = {
                    'pubStartDate': start_str,
                    'pubEndDate': end_str,
                    'resultsPerPage': min(results_per_page, limit - len(all_cves)),
                    'startIndex': start_index
                }
                
                response = requests.get(
                    self.base_url,
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'vulnerabilities' in data:
                        page_cves = data['vulnerabilities']
                        all_cves.extend(page_cves)
                        
                        # Check if we've retrieved all available results
                        total_results = data.get('totalResults', 0)
                        if start_index + len(page_cves) >= total_results:
                            break
                            
                        start_index += len(page_cves)
                    else:
                        break
                elif response.status_code == 403:
                    print("API key required or invalid. Continuing without NVD data.")
                    return []
                else:
                    print(f"API error: {response.status_code}")
                    break
                
                # Respect rate limits
                time.sleep(self.delay)
            
            print(f"Fetched {len(all_cves)} CVEs from NVD")
            return all_cves[:limit]
            
        except Exception as e:
            print(f"NVD fetch failed: {e}")
            return []
    
    def fetch_cve_by_id(self, cve_id):
        """
        Fetch a single CVE by its ID.
        
        Args:
            cve_id: The CVE identifier (e.g., 'CVE-2024-1234')
            
        Returns:
            Raw CVE object or None if not found
        """
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            params = {'cveId': cve_id}
            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    return data['vulnerabilities'][0]
            return None
        except Exception as e:
            print(f"Failed to fetch {cve_id}: {e}")
            return None
    
    def parse_cve(self, cve_data):
        """
        Extract relevant fields from raw NVD API response.
        
        Args:
            cve_data: Raw CVE object from the NVD API
            
        Returns:
            Dictionary with cve_id, description, cvss_score, severity,
            published_date, and last_modified
        """
        try:
            cve = cve_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Extract English description (preferred)
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')
            
            # Extract CVSS score and severity
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            metrics = cve.get('metrics', {})
            
            # Try CVSS v3.1 first (most recent)
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            # Then try v3.0
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            # Finally try v2 (legacy)
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Extract publication date
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
            print(f"Error parsing CVE: {e}")
            return None
    
    def save_to_database(self, db_handler, cve_list):
        """
        Parse CVEs and save them to the database.
        
        Args:
            db_handler: DatabaseHandler instance for saving
            cve_list: List of raw CVE objects from NVD
            
        Returns:
            List of successfully parsed CVEs
        """
        parsed_cves = []
        for cve in cve_list:
            parsed = self.parse_cve(cve)
            if parsed and parsed['description']:  # Only save if we got a description
                parsed_cves.append(parsed)
        
        if parsed_cves:
            db_handler.update_cve_data(parsed_cves)
            print(f"Saved {len(parsed_cves)} CVEs to database")
        return parsed_cves


# Simple test if run directly
if __name__ == "__main__":
    fetcher = NVDFetcher()
    cves = fetcher.fetch_recent_cves(days_back=7, limit=5)
    print(f"Found {len(cves)} CVEs")
    for cve in cves[:3]:
        parsed = fetcher.parse_cve(cve)
        if parsed:
            print(f"{parsed['cve_id']}: {parsed['description'][:100]}...")