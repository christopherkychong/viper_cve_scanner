"""
Overview Dashboard
Provides a high-level view of all CVEs with sector classification and update controls.

This page serves as the main dashboard with:
- Data source status indicators (NVD, EPSS, KEV)
- Manual update button with live output
- Sector tagging (Healthcare, Energy, Other)
- Priority filtering
- Download top 1000 uncategorized CVEs as CSV for keyword discovery
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import streamlit as st
import pandas as pd
import subprocess
import sqlite3
from datetime import datetime
import io

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

def load_cves_with_epss(limit=10000):
    """
    Load CVEs with their EPSS scores, sorted by Priority 1 first, then by EPSS descending.
    """
    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    
    query = """
        SELECT c.cve_id, c.description, c.cvss_score, c.in_kev, e.epss_score
        FROM cves c
        LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
        ORDER BY 
            CASE 
                WHEN c.in_kev = 1 THEN 0
                WHEN e.epss_score > 0.2 AND c.cvss_score > 7.0 THEN 1
                WHEN c.cvss_score > 7.0 THEN 2
                WHEN e.epss_score > 0.2 THEN 3
                ELSE 4
            END,
            e.epss_score DESC NULLS LAST,
            c.cvss_score DESC NULLS LAST
        LIMIT ?
    """
    cursor = conn.execute(query, (limit,))
    rows = cursor.fetchall()
    cves_list = [dict(row) for row in rows]
    conn.close()
    
    return cves_list

def load_top_uncategorized_cves(limit=1000):
    """
    Load top N uncategorized CVEs sorted by priority:
    Priority 1+ (KEV) first, then Priority 1, then Priority 2, then Priority 3, then Priority 4.
    """
    conn = sqlite3.connect(db.db_path)
    
    # Load all CVEs with their scores
    query = """
        SELECT c.cve_id, c.description, c.cvss_score, c.in_kev, 
               COALESCE(e.epss_score, 0) as epss_score
        FROM cves c
        LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Load keywords for sector classification
    healthcare_keywords, energy_keywords = get_keywords_from_filter()
    
    # Filter to uncategorized only
    def is_other(desc):
        if not desc:
            return True
        desc_lower = desc.lower()
        if any(kw.lower() in desc_lower for kw in healthcare_keywords):
            return False
        if any(kw.lower() in desc_lower for kw in energy_keywords):
            return False
        return True
    
    df['is_other'] = df['description'].apply(is_other)
    other_df = df[df['is_other']].copy()
    
    # Calculate priority
    def get_priority(row):
        in_kev = row['in_kev']
        epss = row['epss_score']
        cvss = row['cvss_score']
        
        if in_kev == 1:
            return 0  # Priority 1+ (highest)
        elif epss > 0.2 and cvss > 7.0:
            return 1  # Priority 1
        elif cvss > 7.0:
            return 2  # Priority 2
        elif epss > 0.2:
            return 3  # Priority 3
        else:
            return 4  # Priority 4
    
    other_df['priority_order'] = other_df.apply(get_priority, axis=1)
    
    # Sort by priority_order, then by EPSS desc, then by CVSS desc
    other_df = other_df.sort_values(
        ['priority_order', 'epss_score', 'cvss_score'], 
        ascending=[True, False, False]
    )
    
    # Return top N
    top_df = other_df.head(limit).copy()
    
    # Add priority label for display
    def get_priority_label(row):
        in_kev = row['in_kev']
        epss = row['epss_score']
        cvss = row['cvss_score']
        
        if in_kev == 1:
            return "PRIORITY 1+ (IMMEDIATE)"
        elif epss > 0.2 and cvss > 7.0:
            return "PRIORITY 1 (This week)"
        elif cvss > 7.0:
            return "PRIORITY 2 (Schedule)"
        elif epss > 0.2:
            return "PRIORITY 3 (Monitor)"
        else:
            return "PRIORITY 4 (Deprioritize)"
    
    top_df['priority'] = top_df.apply(get_priority_label, axis=1)
    
    # Select and rename columns for CSV
    result_df = top_df[['cve_id', 'description', 'cvss_score', 'epss_score', 'in_kev', 'priority']].copy()
    result_df['in_kev'] = result_df['in_kev'].map({1: 'Yes', 0: 'No'})
    
    return result_df

def calculate_priority(cvss_score, epss_score, in_kev):
    """Calculate priority label matching export script"""
    if pd.isna(epss_score):
        epss_score = None
    
    if in_kev == 1:
        return "PRIORITY 1+ (IMMEDIATE)"
    elif epss_score is not None and epss_score > 0.2 and cvss_score is not None and cvss_score > 7.0:
        return "PRIORITY 1 (This week)"
    elif cvss_score is not None and cvss_score > 7.0:
        return "PRIORITY 2 (Schedule)"
    elif epss_score is not None and epss_score > 0.2:
        return "PRIORITY 3 (Monitor)"
    elif epss_score is None and cvss_score is None:
        return "PRIORITY UNKNOWN (Missing data)"
    else:
        return "PRIORITY 4 (Deprioritize)"

def get_keywords_from_filter():
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

# Load CVEs for display
all_cves = load_cves_with_epss(limit=10000)

# Add priority label to each CVE
for cve in all_cves:
    cve['priority'] = calculate_priority(
        cve.get('cvss_score'),
        cve.get('epss_score'),
        cve.get('in_kev', 0)
    )

# Get last update information
nvd_update = db.get_last_update('nvd')
epss_update = db.get_last_update('epss')
kev_update = db.get_last_update('kev')

def get_current_counts():
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

def run_updater_with_live_output():
    output_lines = []
    process = subprocess.Popen(
        [sys.executable, "-u", "-m", "src.updater"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    output_placeholder = st.empty()
    
    for line in process.stdout:
        output_lines.append(line)
        output_placeholder.code(''.join(output_lines[-50:]), language="text")
        st.session_state.update_output = "\n".join(output_lines[-50:])
    
    process.wait()
    return process.returncode == 0, "".join(output_lines)

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

# UPDATE BUTTON (No Export Button)
st.sidebar.markdown("---")
st.sidebar.header("🔄 Manual Update")

if st.sidebar.button("🚀 Run Full Update Now", type="primary", use_container_width=True):
    st.session_state.before_counts = get_current_counts()
    st.session_state.update_running = True
    st.session_state.update_output = ""
    st.rerun()

# Show live update output if update is running
if st.session_state.update_running:
    with st.status("Running VIPER Update...", expanded=True) as status:
        success, full_output = run_updater_with_live_output()
        
        st.session_state.after_counts = get_current_counts()
        st.session_state.update_success = success
        st.session_state.update_message = "✅ Update completed successfully!" if success else "❌ Update failed"
        st.session_state.update_timestamp = datetime.now()
        st.session_state.update_output = full_output
        st.session_state.update_running = False
        
        if success:
            status.update(label="✅ Update Complete!", state="complete")
        else:
            status.update(label="❌ Update Failed", state="error")
    
    st.rerun()

# Display update output if available
if st.session_state.update_output and not st.session_state.update_running:
    with st.expander("📋 Last Update Output", expanded=False):
        st.text(st.session_state.update_output)

# Show detailed update confirmation
if st.session_state.update_success and st.session_state.before_counts and st.session_state.after_counts:
    st.success(f"✅ {st.session_state.update_message}")
    st.balloons()
    
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
    
    if after['cves'] > 0:
        st.info(f"✅ Verified: {after['cves']} CVEs are now in the database table.")
    else:
        st.warning("⚠️ Warning: Database table appears empty after update!")
    
    st.caption(f"Update completed at: {st.session_state.update_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if st.button("Clear confirmation"):
        st.session_state.update_success = False
        st.session_state.before_counts = None
        st.session_state.after_counts = None
        st.session_state.update_output = ""
        st.rerun()
    
    st.markdown("---")

# Check if NVD data exists
if not nvd_update or nvd_update[1] == 0:
    st.error("""
        🚨 **CRITICAL: No NVD Data Found**
        
        VIPER requires NVD CVE descriptions to function. 
        Please run the updater immediately: python -m src.updater """)

# =========================================================
# MAIN CONTENT - Sector Tagging and Table
# =========================================================
st.markdown("---")

HEALTHCARE_KEYWORDS, ENERGY_KEYWORDS = get_keywords_from_filter()

# Process CVEs with sector tags
if all_cves:
    for cve in all_cves:
        desc = cve.get('description', '').lower()
        sectors = []
        
        if any(kw.lower() in desc for kw in HEALTHCARE_KEYWORDS):
            sectors.append("🏥 Healthcare")
        if any(kw.lower() in desc for kw in ENERGY_KEYWORDS):
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
    st.subheader("📋 CVEs (Sorted by Priority 1 First, then by EPSS)")
    
    # Select columns for display
    display_cols = ['cve_id', 'description', 'cvss_score', 'epss_score', 'priority', 'sector', 'in_kev']
    available_cols = [col for col in display_cols if col in df.columns]
    
    # Format KEV for display
    if 'in_kev' in df.columns:
        df['in_kev_display'] = df['in_kev'].map({1: '✅ Yes', 0: '❌ No'})
        available_cols = [c if c != 'in_kev' else 'in_kev_display' for c in available_cols]
    
    # Rename columns
    rename_map = {
        'cve_id': 'CVE ID',
        'description': 'Description',
        'cvss_score': 'CVSS',
        'epss_score': 'EPSS',
        'priority': 'Priority',
        'sector': 'Sector',
        'in_kev_display': 'In KEV'
    }
    
    display_df = df[available_cols].rename(columns=rename_map)
    
    st.dataframe(
        display_df.head(500),
        use_container_width=True,
        height=600
    )
    
    # Filter by priority dropdown
    st.markdown("### 🔍 Filter by Priority")
    priority_filter_options = ["All", "PRIORITY 1+ (IMMEDIATE)", "PRIORITY 1 (This week)", "PRIORITY 2 (Schedule)", "PRIORITY 3 (Monitor)", "PRIORITY 4 (Deprioritize)", "PRIORITY UNKNOWN (Missing data)"]
    selected_priority = st.selectbox("Choose priority level", priority_filter_options)
    
    if selected_priority != "All":
        filtered = display_df[display_df['Priority'] == selected_priority]
        st.dataframe(filtered, use_container_width=True, height=400)
    
    # =========================================================
    # DOWNLOAD TOP 1000 UNCATEGORIZED CVEs AS CSV
    # =========================================================
    st.markdown("---")
    st.subheader("📥 Download Uncategorized CVEs for Keyword Discovery")
    st.caption("CVEs marked as 'Other' have not matched any healthcare or energy keywords.")
    st.caption("Sorted by priority: Priority 1+ (KEV) first, then Priority 1, Priority 2, Priority 3.")
    st.caption("Download the CSV file to analyze in Excel or other spreadsheet programs.")
    
    # Load top 1000 uncategorized CVEs (prioritized)
    top_uncategorized_df = load_top_uncategorized_cves(limit=1000)
    
    if not top_uncategorized_df.empty:
        # Create CSV in memory
        csv_buffer = io.StringIO()
        top_uncategorized_df.to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()
        
        # Count priorities for display
        p1plus_count = len(top_uncategorized_df[top_uncategorized_df['priority'] == "PRIORITY 1+ (IMMEDIATE)"])
        p1_count = len(top_uncategorized_df[top_uncategorized_df['priority'] == "PRIORITY 1 (This week)"])
        p2_count = len(top_uncategorized_df[top_uncategorized_df['priority'] == "PRIORITY 2 (Schedule)"])
        p3_count = len(top_uncategorized_df[top_uncategorized_df['priority'] == "PRIORITY 3 (Monitor)"])
        p4_count = len(top_uncategorized_df[top_uncategorized_df['priority'] == "PRIORITY 4 (Deprioritize)"])
        
        st.info(f"""
        **Top 1000 Uncategorized CVEs by Priority:**
        - 🔴 Priority 1+ (KEV): {p1plus_count}
        - 🟠 Priority 1 (CVSS>7.0 & EPSS>0.2): {p1_count}
        - 🟡 Priority 2 (CVSS>7.0 only): {p2_count}
        - 🟢 Priority 3 (EPSS>0.2 only): {p3_count}
        - ⚪ Priority 4 (Lower priority): {p4_count}
        """)
        
        # Download button
        st.download_button(
            label="📥 Download Top 1000 Uncategorized CVEs (CSV)",
            data=csv_data,
            file_name=f"uncategorized_cves_top1000_{datetime.now().strftime('%Y-%m-%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )
        
        st.caption(f"Showing top 1000 of {other_count:,} total uncategorized CVEs.")
    else:
        st.success("🎉 No uncategorized CVEs found!")

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