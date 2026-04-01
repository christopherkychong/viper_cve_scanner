# 🛡️ VIPER - Vulnerability Intelligence Platform

A customizable threat intelligence tool that prioritizes CVEs for Australian healthcare and energy sectors using EPSS, NVD, and CISA KEV data.

## 🎯 Purpose

VIPER helps security teams focus on what matters by:
- Automatically fetching the latest vulnerability data daily
- Tagging CVEs as Healthcare or Energy based on keywords
- Prioritizing based on exploitation probability (EPSS) and confirmed exploits (KEV)
- Providing an intuitive dashboard for quick analysis

## ✨ Features

### Data Sources
- 📊 **EPSS Scores** - Daily exploitation probability for 10,000+ CVEs
- 📋 **NVD Database** - Complete vulnerability descriptions and CVSS scores
- 🔥 **CISA KEV** - Confirmed actively exploited vulnerabilities

### Sector Filtering
- 🏥 **Healthcare** - Medical devices, hospital IT, healthcare vendors
- ⚡ **Energy** - OT/ICS systems, industrial infrastructure, energy vendors

### Dashboard Pages
- **Overview** - High-level metrics, update controls, uncategorized exports
- **Healthcare Sector** - Filtered healthcare vulnerabilities with device categorization
- **Energy Sector** - Filtered energy vulnerabilities with protocol/vendor analysis
- **Keyword Management** - Full control over sector keywords with backup/restore

### Smart Prioritization
- 🔴 **PRIORITY 1+ (IMMEDIATE)** - Confirmed exploited (in KEV)
- 🟠 **PRIORITY 1 (This week)** - EPSS > 0.2 and CVSS > 7.0
- 🟡 **PRIORITY 2 (Schedule)** - CVSS > 7.0
- 🟢 **PRIORITY 3 (Monitor)** - EPSS > 0.2
- ⚪ **PRIORITY 4 (Deprioritize)** - Low severity, low probability

### Australian Timezone Support
- 🇦🇺 All times displayed in AEDT/AEST
- Daily EPSS updates at 10pm AEDT
- Energy sector refreshes Tuesday 1am AEDT
- Healthcare sector updates on 2nd of month 2am AEDT

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Git
- Internet connection for data fetching

### Installation

```bash
# Clone the repository
git clone https://github.com/christopherkychong/viper_cve_scanner.git
cd viper_cve_scanner

# Create and activate virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the initial data update
python -m src.updater

# Launch the dashboard
# Note: On some systems (like macOS), you may need to use python3 instead of python
python main.py
```

### First-Time Setup
1. Run `python -m src.updater` to fetch initial data (may take 5-10 minutes)
2. Launch dashboard with `python main.py` (or `python3 main.py` on some systems)
3. Navigate to `http://localhost:8501` in your browser
4. Explore the Healthcare and Energy dashboards

## 📁 Project Structure

```
viper_cve_scanner/
├── src/
│   ├── dashboard/              # Streamlit web interface
│   │   ├── pages/              # Individual dashboard pages
│   │   │   ├── 01_Overview.py
│   │   │   ├── 05_Healthcare_Sector.py
│   │   │   ├── 06_Energy_Sector.py
│   │   │   └── 07_Keyword_Management.py
│   │   └── app.py              # Main dashboard app
│   ├── utils/                  # Core utilities
│   │   ├── database_handler.py  # SQLite database operations
│   │   ├── industry_filters.py  # Keyword filtering logic
│   │   └── keywords.json        # Sector keywords (editable)
│   ├── data_collection/         # Data fetchers
│   │   └── epss_fetcher.py
│   ├── kev_fetcher.py           # CISA KEV fetcher
│   ├── nvd_fetcher.py           # NVD API fetcher
│   └── updater.py               # Master update coordinator
├── data/                        # SQLite database and cached data
├── main.py                       # Application entry point
├── requirements.txt              # Python dependencies
└── .gitignore                    # Git ignore rules
```

## 📊 Usage Guide

### Daily Workflow
1. Launch dashboard: `python main.py` (or `python3 main.py` on some systems)
2. Check Overview page for data freshness
3. Review uncategorized CVEs for new keyword opportunities
4. Examine Healthcare and Energy dashboards for high-priority CVEs
5. Add discovered keywords via Keyword Management page

### Managing Keywords
1. Go to Keyword Management page
2. Edit any category by typing keywords (one per line)
3. Click "Save All Keywords" (automatic backup created)
4. Use Backup Management to restore previous versions if needed

### Manual Updates
- Click "Run Full Update Now" in Overview sidebar
- Watch live terminal output in the UI
- Confirmation shows before/after record counts

## 🔧 Troubleshooting

### No Data Showing
- Run `python -m src.updater` manually
- Check internet connection
- Verify data files exist in `data/` directory

### Keywords Not Working
- Check Keyword Management page shows your keywords
- Verify keywords appear in CVE descriptions
- Try a common word like "vulnerability" to test

### Dashboard Won't Start
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt`
- Check for Python version compatibility (3.8+)
- On macOS, try `python3 main.py` instead of `python main.py`

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- EPSS data provided by [FIRST.org](https://www.first.org/epss/)
- NVD data from [NIST](https://nvd.nist.gov/)
- KEV catalog from [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)