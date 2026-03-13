"""
Master Updater for VIPER
Runs all data fetchers in sequence with proper error handling.

This module orchestrates the complete update process:
1. EPSS scores (nice to have, non-critical)
2. NVD CVE data (CRITICAL - app cannot function without descriptions)
3. CISA KEV catalog (enhancement, non-critical)

NVD is treated as critical because without descriptions, sector filtering
and vulnerability understanding is impossible. If NVD fails, the entire
update is aborted to prevent inconsistent data.
"""

import sys
from datetime import datetime
from pathlib import Path
from src.nvd_fetcher import NVDFetcher
from src.kev_fetcher import KEVFetcher
from src.data_collection.epss_fetcher import EPSSFetcher
from src.utils.database_handler import DatabaseHandler

class VIPERUpdater:
    """
    Orchestrates all data updates with proper error handling.
    
    NVD updates are treated as critical failures - if NVD returns no data,
    the entire update is aborted to prevent database corruption. EPSS and KEV
    updates are allowed to fail without aborting the update.
    """
    
    def __init__(self, nvd_api_key=None):
        """Initialize all data fetchers and the database handler."""
        self.nvd_fetcher = NVDFetcher(api_key=nvd_api_key)
        self.kev_fetcher = KEVFetcher()
        self.epss_fetcher = EPSSFetcher()
        self.db = DatabaseHandler()
    
    def run_all_updates(self):
        """
        Execute the complete update cycle with proper error handling.
        
        Returns:
            True if update successful (NVD succeeded), False if NVD failed
        """
        print("\n" + "="*60)
        print(f"VIPER UPDATE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Step 1: EPSS Scores (nice to have, not critical)
        print("\nSTEP 1: EPSS Scores")
        epss_success = self.epss_fetcher.update_database()
        if epss_success:
            print("EPSS update successful")
        else:
            print("WARNING: EPSS update failed - continuing anyway")
        
        # Step 2: NVD CVE Data (CRITICAL - app cannot function without this)
        print("\nSTEP 2: NVD CVE Data (CRITICAL)")
        print("Fetching CVEs from last 30 days...")
        
        cves = self.nvd_fetcher.fetch_recent_cves(days_back=30, limit=1000)
        
        # Check if NVD returned any data
        if not cves:
            print("\n" + "!"*60)
            print("CRITICAL FAILURE: NVD FETCH RETURNED NO DATA")
            print("VIPER cannot function without CVE descriptions")
            print("Update ABORTED - no data saved")
            print("!"*60 + "\n")
            return False
        
        # Save NVD data to database
        save_success = self.nvd_fetcher.save_to_database(self.db, cves)
        
        if not save_success:
            print("\n" + "!"*60)
            print("CRITICAL FAILURE: NVD DATA COULD NOT BE SAVED TO DATABASE")
            print("Update ABORTED - database may be corrupted")
            print("!"*60 + "\n")
            return False
        
        print("NVD update successful - database populated")
        
        # Step 3: CISA KEV Catalog (enhancement, not critical)
        print("\nSTEP 3: CISA KEV Catalog")
        kev_data = self.kev_fetcher.fetch_catalog()
        if kev_data:
            kev_set = self.kev_fetcher.get_kev_set()
            self.db.update_kev_status(kev_set)
            print("KEV update successful")
        else:
            print("WARNING: KEV update failed - continuing anyway")
        
        print("\n" + "="*60)
        print("UPDATE COMPLETE - ALL CRITICAL SYSTEMS GO")
        print(f"NVD: {len(cves)} CVEs loaded")
        print("="*60 + "\n")
        return True
    
    def run_epss_only(self):
        """Run only the EPSS update (for testing or manual refresh)."""
        print("Running EPSS update only...")
        self.epss_fetcher.update_database()
    
    def run_nvd_only(self):
        """
        Run only the NVD update (CRITICAL).
        
        Returns:
            True if successful, False otherwise
        """
        print("Running NVD update only (CRITICAL)...")
        cves = self.nvd_fetcher.fetch_recent_cves(days_back=30, limit=1000)
        if cves:
            self.nvd_fetcher.save_to_database(self.db, cves)
            print("NVD update successful")
            return True
        else:
            print("CRITICAL ERROR: NVD update FAILED")
            return False
    
    def run_kev_only(self):
        """Run only the KEV update (for testing or manual refresh)."""
        print("Running KEV update only...")
        kev_data = self.kev_fetcher.fetch_catalog()
        if kev_data:
            kev_set = self.kev_fetcher.get_kev_set()
            self.db.update_kev_status(kev_set)


# Command-line interface for running updates
if __name__ == "__main__":
    updater = VIPERUpdater()
    
    # Parse command line arguments for selective updates
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'epss':
            updater.run_epss_only()
        elif cmd == 'nvd':
            success = updater.run_nvd_only()
            if not success:
                sys.exit(1)  # Exit with error code for scripting
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