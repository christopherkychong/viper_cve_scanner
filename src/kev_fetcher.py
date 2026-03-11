"""
CISA KEV (Known Exploited Vulnerabilities) Fetcher
Downloads and parses the CISA KEV catalog.

The KEV catalog contains vulnerabilities that are confirmed to be actively
exploited in the wild. This is a critical data source for prioritization
- any CVE in KEV should be patched immediately regardless of its EPSS score.
"""

import requests
import json
from pathlib import Path
from datetime import datetime

class KEVFetcher:
    """
    Fetches the CISA KEV catalog and provides methods to check if CVEs are actively exploited.
    
    The KEV catalog is updated regularly and contains vulnerabilities that have been
    confirmed as exploited in the wild. This class handles downloading, caching,
    and providing access to the exploited CVE list.
    """
    
    def __init__(self):
        """Initialize the KEV fetcher with API endpoint and local storage paths."""
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.data_dir = Path("data/kev")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.data_file = self.data_dir / "kev_catalog.json"
    
    def fetch_catalog(self):
        """
        Download the latest KEV catalog from CISA.
        
        Returns:
            The complete JSON response from CISA, or None if download fails
        """
        print("Fetching CISA KEV catalog...")
        
        try:
            response = requests.get(self.url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                # Save raw data to cache
                with open(self.data_file, 'w') as f:
                    json.dump(data, f, indent=2)
                
                print(f"KEV catalog updated: {data.get('count', 0)} vulnerabilities")
                return data
            else:
                print(f"KEV API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"KEV fetch failed: {e}")
            return None
    
    def get_kev_set(self):
        """
        Return a set of all CVE IDs that are in the KEV catalog.
        
        This is the primary method used by the database handler to mark
        exploited CVEs. Using a set allows for fast O(1) lookups.
        
        Returns:
            Set of CVE ID strings that are actively exploited
        """
        # Try to load from cache first
        if not self.data_file.exists():
            data = self.fetch_catalog()
            if not data:
                return set()
        else:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
        
        # Extract all CVE IDs from the catalog
        kev_set = set()
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID')
            if cve_id:
                kev_set.add(cve_id)
        
        return kev_set
    
    def is_in_kev(self, cve_id):
        """
        Check if a specific CVE is in the KEV catalog.
        
        Args:
            cve_id: The CVE identifier to check
            
        Returns:
            True if the CVE is actively exploited, False otherwise
        """
        kev_set = self.get_kev_set()
        return cve_id in kev_set


# Simple test when run directly
if __name__ == "__main__":
    fetcher = KEVFetcher()
    data = fetcher.fetch_catalog()
    if data:
        kev_set = fetcher.get_kev_set()
        print(f"Sample KEV CVEs: {list(kev_set)[:5]}")