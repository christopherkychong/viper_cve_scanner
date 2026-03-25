"""
Overview Dashboard
Provides a high-level view of all CVEs with sector classification and update controls.

This page serves as the main dashboard with:
- Data source status indicators (NVD, EPSS, KEV)
- Manual update button with live output
- Sector tagging (Healthcare, Energy, Other)
- Priority filtering
- Export functionality for uncategorized CVEs
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import streamlit as st
import pandas as pd
import subprocess
import sqlite3
from datetime import datetime

# Force reload keywords from file on every page load
import importlib
import src.utils.industry_filters
importlib.reload(src.utils.industry_filters)
from src.utils.industry_filters import industry_filter

from src.utils.database_handler import DatabaseHandler

st.set_page_config(page_title="Overview", layout="wide")
st.title("📊 Vulnerability Overview")

# Initialize session state for update tracking
if 'update_success' not in st.session_state:
    st.session_state.update_success = False
if 'update_message' not in st.session_state:
    st.session_state.update_message = ""
if 'update_timestamp' not in st.session_state:
    st.session_state.update_timestamp = None
if 'before_counts' not in st.session_state:
    st.session_state.before_counts = None
if 'after_counts' not in st.session_state:
    st.session_state.after_counts = None
if 'update_output' not in st.session_state:
    st.session_state.update_output = ""
if 'update_running' not in st.session_state:
    st.session_state.update_running = False

db = DatabaseHandler()
all_cves = db.get_all_cves(limit=1000)

# Get last update information for each data source
nvd_update = db.get_last_update('nvd')
epss_update = db.get_last_update('epss')
kev_update = db.get_last_update('kev')

def get_current_counts():
    """
    Get current record counts from the database.
    
    Returns:
        Dictionary with counts for cves, epss_scores, and kev records
    """
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM cves")
    cves_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM epss_scores")
    epss_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM updates WHERE source='kev'")
    kev_result = cursor.fetchone()
    kev_count = kev_result[0] if kev_result else 0
    
    conn.close()
    return {
        'cves': cves_count,
        'epss': epss_count,
        'kev': kev_count
    }

def run_updater_with_output():
    """
    Run the updater and capture real-time output for display.
    
    Returns:
        Tuple of (success boolean, complete output string)
    """
    output = []
    process = subprocess.Popen(
        [sys.executable, "-m", "src.updater"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    for line in process.stdout:
        output.append(line)
        # Keep only the last 50 lines to avoid memory issues
        st.session_state.update_output = "\n".join(output[-50:])
    
    process.wait()
    return process.returncode == 0, "\n".join(output)

# SIDEBAR - Data Source Status
st.sidebar.header("📊 Data Source Status")

if nvd_update:
    last_run, count = nvd_update
    st.sidebar.success(f"✅ NVD: {count} CVEs")
    st.sidebar.caption(f"Last: {last_run[:16]}")
else:
    st.sidebar.warning("⚠️ NVD: No data")

if epss_update:
    last_run, count = epss_update
    st.sidebar.success(f"✅ EPSS: {count} scores")
    st.sidebar.caption(f"Last: {last_run[:16]}")
else:
    st.sidebar.warning("⚠️ EPSS: No data")

if kev_update:
    last_run, count = kev_update
    st.sidebar.success(f"✅ KEV: {count} exploited")
    st.sidebar.caption(f"Last: {last_run[:16]}")
else:
    st.sidebar.warning("⚠️ KEV: No data")

# UPDATE BUTTON
st.sidebar.markdown("---")
st.sidebar.header("🔄 Manual Update")

if st.sidebar.button("🚀 Run Full Update Now", type="primary", use_container_width=True):
    # Store counts before update for comparison
    st.session_state.before_counts = get_current_counts()
    st.session_state.update_running = True
    st.session_state.update_output = ""
    st.rerun()

# Show live update output if update is running
if st.session_state.update_running:
    st.subheader("📟 Live Update Output")
    success, full_output = run_updater_with_output()
    
    # Get counts after update for comparison
    st.session_state.after_counts = get_current_counts()
    st.session_state.update_success = success
    st.session_state.update_message = "✅ Update completed successfully!" if success else "❌ Update failed"
    st.session_state.update_timestamp = datetime.now()
    st.session_state.update_running = False
    st.session_state.update_output = full_output
    st.rerun()

# Display update output if available
if st.session_state.update_output and not st.session_state.update_running:
    with st.expander("📋 Last Update Output", expanded=False):
        st.text(st.session_state.update_output)

# Show detailed update confirmation with before/after counts
if st.session_state.update_success and st.session_state.before_counts and st.session_state.after_counts:
    st.success(f"✅ {st.session_state.update_message}")
    st.balloons()
    
    # Calculate and display changes
    before = st.session_state.before_counts
    after = st.session_state.after_counts
    
    col1, col2, col3 = st.columns(3)
    with col1:
        nvd_change = after['cves'] - before['cves']
        st.metric(
            "📋 NVD CVEs",
            after['cves'],
            delta=f"+{nvd_change}" if nvd_change > 0 else "No change"
        )
    with col2:
        epss_change = after['epss'] - before['epss']
        st.metric(
            "📊 EPSS Scores",
            after['epss'],
            delta=f"+{epss_change}" if epss_change > 0 else "No change"
        )
    with col3:
        kev_change = after['kev'] - before['kev']
        st.metric(
            "🔥 KEV Entries",
            after['kev'],
            delta=f"+{kev_change}" if kev_change > 0 else "No change"
        )
    
    # Verify database was populated
    if after['cves'] > 0:
        st.info(f"✅ Verified: {after['cves']} CVEs are now in the database table.")
    else:
        st.warning("⚠️ Warning: Database table appears empty after update!")
    
    st.caption(f"Update completed at: {st.session_state.update_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Clear button to dismiss confirmation
    if st.button("Clear confirmation"):
        st.session_state.update_success = False
        st.session_state.before_counts = None
        st.session_state.after_counts = None
        st.session_state.update_output = ""
        st.rerun()
    
    st.markdown("---")

# Check if NVD data exists - if not, show critical warning
if not nvd_update or nvd_update[1] == 0:
    st.error("""
        🚨 **CRITICAL: No NVD Data Found**
        
        VIPER requires NVD CVE descriptions to function. 
        Please run the updater immediately: python -m src.updater """)

# MAIN CONTENT - Sector Tagging
st.markdown("---")

def get_keywords_from_filter():
    """
    Extract all healthcare and energy keywords from the industry filter.
    
    Returns:
        Tuple of (healthcare_keywords list, energy_keywords list)
    """
    try:
        healthcare_keywords = []
        energy_keywords = []
        
        if hasattr(industry_filter, 'keywords'):
            if 'healthcare' in industry_filter.keywords:
                for cat in industry_filter.keywords['healthcare'].values():
                    healthcare_keywords.extend(cat)
            if 'energy' in industry_filter.keywords:
                for cat in industry_filter.keywords['energy'].values():
                    energy_keywords.extend(cat)
        
        return healthcare_keywords, energy_keywords
    except Exception as e:
        st.error(f"Error getting keywords: {e}")
        return [], []

# Load keywords from filter
HEALTHCARE_KEYWORDS, ENERGY_KEYWORDS = get_keywords_from_filter()

# Process CVEs with sector tags
if all_cves:
    for cve in all_cves:
        desc = cve.get('description', '').lower()
        sectors = []
        
        if any(k.lower() in desc for k in HEALTHCARE_KEYWORDS):
            sectors.append("🏥 Healthcare")
        if any(k.lower() in desc for k in ENERGY_KEYWORDS):
            sectors.append("⚡ Energy")
        
        cve['sector'] = ', '.join(sectors) if sectors else '📦 Other'
    
    df = pd.DataFrame(all_cves)
    
    # Count CVEs by sector
    healthcare_count = len(df[df['sector'].str.contains('Healthcare', na=False)])
    energy_count = len(df[df['sector'].str.contains('Energy', na=False)])
    other_count = len(df[df['sector'] == '📦 Other'])
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total CVEs", len(df))
    with col2:
        st.metric("🏥 Healthcare", healthcare_count)
    with col3:
        st.metric("⚡ Energy", energy_count)
    with col4:
        st.metric("📦 Other", other_count)
    
    st.markdown("---")
    
    # Show current active keywords
    with st.expander("📋 Current Active Keywords"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🏥 Healthcare Keywords:**")
            for kw in sorted(HEALTHCARE_KEYWORDS):
                st.markdown(f"- `{kw}`")
        with col2:
            st.markdown("**⚡ Energy Keywords:**")
            for kw in sorted(ENERGY_KEYWORDS):
                st.markdown(f"- `{kw}`")
    
    st.markdown("---")
    
    # Main data table
    st.subheader("📋 CVEs with Priority and Sector")
    
    display_cols = ['cve_id', 'description', 'cvss_score', 'epss_score', 
                    'priority', 'sector', 'in_kev']
    
    # Format boolean for display
    if 'in_kev' in df.columns:
        df['in_kev'] = df['in_kev'].map({1: '✅ Yes', 0: '❌ No'})
    
    # Rename columns for readability
    display_df = df[display_cols].rename(columns={
        'cve_id': 'CVE ID',
        'description': 'Description',
        'cvss_score': 'CVSS',
        'epss_score': 'EPSS',
        'priority': 'Priority',
        'sector': 'Sector',
        'in_kev': 'In KEV'
    })
    
    st.dataframe(
        display_df.head(500),
        use_container_width=True,
        height=600
    )
    
    # Filter by priority
    st.markdown("### 🔍 Filter by Priority")
    priority_options = ["All", "🔴 PRIORITY 1+", "🟠 PRIORITY 1", "🟡 PRIORITY 2", "🟢 PRIORITY 3", "⚪ PRIORITY 4"]
    selected = st.selectbox("Choose priority level", priority_options)
    
    if selected != "All":
        filtered = display_df[display_df['Priority'].str.contains(selected[:10])]
        st.dataframe(filtered, use_container_width=True, height=400)
    
    # Export uncategorized CVEs for analysis
    st.markdown("### 📤 Export Uncategorized CVEs")
    st.caption("CVEs marked as 'Other' can be analyzed in external tools to discover new keywords.")
    
    other_cves = df[df['sector'] == '📦 Other'][['cve_id', 'description']].head(50)
    
    if not other_cves.empty:
        # Format for easy copying
        export_text = ""
        for _, row in other_cves.iterrows():
            export_text += f"{row['cve_id']}: {row['description']}\n\n"
        
        col1, col2 = st.columns([1, 3])
        with col1:
            st.code(export_text, language="text")
            
        with col2:
            st.info("""
                💡 **How to use:**
                1. Click the copy button in the top-right corner
                2. Paste into your preferred analysis tool
                3. Look for common terms or patterns
                4. Add new keywords via the Keyword Management page
            """)
        
        st.caption(f"Showing {len(other_cves)} uncategorized CVEs")
    else:
        st.success("🎉 No uncategorized CVEs!")

else:
    st.warning("No CVE data available. Run updater first.")
    if st.button("🔄 Run Initial Update"):
        with st.spinner("Running first-time update..."):
            result = subprocess.run([sys.executable, "-m", "src.updater"], capture_output=True)
            if result.returncode == 0:
                st.success("✅ Update complete! Refreshing...")
                st.rerun()
            else:
                st.error("❌ Update failed")