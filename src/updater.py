"""
Master Updater for VIPER
Runs all data fetchers in sequence
NVD is CRITICAL - update fails if NVD fails
"""

import time
import sys
from datetime import datetime
from pathlib import Path
from src.nvd_fetcher import NVDFetcher
from src.kev_fetcher import KEVFetcher
from src.data_collection.epss_fetcher import EPSSFetcher
from src.utils.database_handler import DatabaseHandler

class VIPERUpdater:
    """Orchestrates all data updates - NVD is CRITICAL"""
    
    def __init__(self, nvd_api_key=None):
        self.nvd_fetcher = NVDFetcher(api_key=nvd_api_key)
        self.kev_fetcher = KEVFetcher()
        self.epss_fetcher = EPSSFetcher()
        self.db = DatabaseHandler()
        
    def run_all_updates(self):
        """Run complete update cycle - NVD failure stops everything"""
        print("\n" + "="*60)
        print(f"VIPER UPDATE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Step 1: CISA KEV Catalog (fastest, provides immediate feedback)
        print("\nSTEP 1: CISA KEV Catalog")
        kev_data = self.kev_fetcher.fetch_catalog()
        if kev_data:
            kev_set = self.kev_fetcher.get_kev_set()
            self.db.update_kev_status(kev_set)
            print("KEV update successful")
        else:
            print("WARNING: KEV update failed - continuing anyway")
        
        # Step 2: NVD CVE Data (CRITICAL - fetch ALL CVEs in batches)
        print("\nSTEP 2: NVD CVE Data (CRITICAL)")
        print("Fetching ALL CVEs from NVD in batches (this may take 10-30 minutes)...")
        
        success = self.nvd_fetcher.fetch_cves_by_current_year(self.db)
        
        if not success:
            print("\n" + "!"*60)
            print("CRITICAL FAILURE: NVD FETCH FAILED")
            print("VIPER cannot function without CVE descriptions")
            print("Update ABORTED - no data saved")
            print("!"*60 + "\n")
            return False
        
        print("NVD update successful - database populated")
        
        # Step 3: EPSS Scores (nice to have, not critical)
        print("\nSTEP 3: EPSS Scores")
        epss_success = self.epss_fetcher.update_database()
        if epss_success:
            print("EPSS update successful")
        else:
            print("WARNING: EPSS update failed - continuing anyway")
        
        print("\n" + "="*60)
        print("UPDATE COMPLETE - ALL CRITICAL SYSTEMS GO")
        print("="*60 + "\n")
        return True
    
    def run_epss_only(self):
        """Run only EPSS update"""
        print("Running EPSS update only...")
        self.epss_fetcher.update_database()
    
    def run_nvd_only(self):
        """Run only NVD update (CRITICAL) - fetches CVEs for current year"""
        print("Running NVD update only (fetching CVEs for current year)...")
        success = self.nvd_fetcher.fetch_cves_by_current_year(self.db)
        if success:
            print("NVD update successful")
            return True
        else:
            print("CRITICAL ERROR: NVD update FAILED")
            return False
    
    def run_kev_only(self):
        """Run only KEV update"""
        print("Running KEV update only...")
        kev_data = self.kev_fetcher.fetch_catalog()
        if kev_data:
            kev_set = self.kev_fetcher.get_kev_set()
            self.db.update_kev_status(kev_set)


if __name__ == "__main__":
    import sys
    
    updater = VIPERUpdater()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'epss':
            updater.run_epss_only()
        elif cmd == 'nvd':
            success = updater.run_nvd_only()
            if not success:
                sys.exit(1)
        elif cmd == 'kev':
            updater.run_kev_only()
        else:
            success = updater.run_all_updates()
            if not success:
                sys.exit(1)
    else:
        success = updater.run_all_updates()
        if not success:
            sys.exit(1)
    
    # Force exit to ensure process terminates
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(0)