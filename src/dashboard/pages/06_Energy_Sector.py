"""
Energy Sector Dashboard
Shows CVEs filtered by energy keywords from industry_filters.py
Force reloads keywords on every page load
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import subprocess
import sqlite3
from datetime import datetime

# Force reload keywords from file on every page load
from src.utils.industry_filters import industry_filter

from src.utils.database_handler import DatabaseHandler

# Force reload keywords from file on EVERY page load
import importlib
import src.utils.industry_filters
importlib.reload(src.utils.industry_filters)
from src.utils.industry_filters import industry_filter

st.set_page_config(page_title="Energy Sector", layout="wide")
st.title("⚡ Energy Sector Vulnerabilities")

db = DatabaseHandler()

def load_cves_for_energy(limit=10000):
    """
    Load CVEs with EPSS scores, sorted by Priority 1 first, then by EPSS descending.
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

def calculate_priority(cvss_score, epss_score, in_kev):
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

# Load CVEs
all_cves = load_cves_for_energy(limit=10000)

# Add priority label
for cve in all_cves:
    cve['priority'] = calculate_priority(
        cve.get('cvss_score'),
        cve.get('epss_score'),
        cve.get('in_kev', 0)
    )

# Get all energy keywords from industry_filters.py
def get_energy_keywords():
    try:
        if hasattr(industry_filter, 'keywords'):
            if 'energy' in industry_filter.keywords:
                energy_keywords = []
                for category, keywords in industry_filter.keywords['energy'].items():
                    energy_keywords.extend(keywords)
                return energy_keywords
        return []
    except Exception as e:
        st.error(f"Error loading energy keywords: {e}")
        return []

ENERGY_KEYWORDS = get_energy_keywords()

if all_cves:
    # Filter for energy using ALL keywords
    energy_cves = []
    matched_keywords = set()
    
    for cve in all_cves:
        desc = cve.get('description', '').lower()
        matched = []
        for kw in ENERGY_KEYWORDS:
            if kw.lower() in desc:
                matched.append(kw)
                matched_keywords.add(kw)
        if matched:
            cve['matched_keywords'] = ', '.join(matched[:3])
            energy_cves.append(cve)
    
    if energy_cves:
        df = pd.DataFrame(energy_cves)
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Energy CVEs", len(df))
        with col2:
            critical = len(df[df['priority'].str.contains('PRIORITY 1', na=False)])
            st.metric("Priority 1+1", critical)
        with col3:
            exploited = len(df[df['in_kev'] == 1])
            st.metric("Actively Exploited", exploited)
        with col4:
            high_epss = len(df[df['epss_score'] > 0.5])
            st.metric("High EPSS (>0.5)", high_epss)
        
        # Show current keywords being used
        with st.expander(f"📋 Current Energy Keywords ({len(ENERGY_KEYWORDS)} total)"):
            col1, col2 = st.columns(2)
            
            if matched_keywords:
                with col1:
                    st.markdown("**✅ Keywords that matched CVEs:**")
                    for kw in sorted(matched_keywords):
                        st.markdown(f"- `{kw}`")
            
            with col2:
                st.markdown("**📋 All tracked keywords:**")
                for kw in sorted(ENERGY_KEYWORDS):
                    st.markdown(f"- `{kw}`")
        
        st.markdown("---")
        
        # OT Protocol Analysis
        st.subheader("OT Protocol Analysis")
        
        protocols = ['modbus', 'dnp3', 'profibus', 'opc', 'iec61850', 'bacnet', 'profinet']
        protocol_counts = {}
        
        if 'description' in df.columns:
            for protocol in protocols:
                count = df['description'].str.lower().str.contains(protocol, na=False).sum()
                if count > 0:
                    protocol_counts[protocol.upper()] = count
            
            if protocol_counts:
                protocol_df = pd.DataFrame([
                    {'Protocol': k, 'Count': v} for k, v in protocol_counts.items()
                ]).sort_values('Count', ascending=False)
                
                fig = px.bar(
                    protocol_df,
                    x='Protocol',
                    y='Count',
                    title='CVEs by OT Protocol',
                    color='Count',
                    color_continuous_scale='reds'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # Vendor analysis
        st.subheader("Vendor Analysis")
        vendors = ['siemens', 'schneider', 'rockwell', 'abb', 'honeywell', 'emerson', 'ge']
        vendor_counts = {}
        
        if 'description' in df.columns:
            for vendor in vendors:
                count = df['description'].str.lower().str.contains(vendor, na=False).sum()
                if count > 0:
                    vendor_counts[vendor.title()] = count
            
            if vendor_counts:
                vendor_df = pd.DataFrame([
                    {'Vendor': k, 'Count': v} for k, v in vendor_counts.items()
                ]).sort_values('Count', ascending=False)
                
                fig = px.pie(
                    vendor_df,
                    values='Count',
                    names='Vendor',
                    title='CVEs by Vendor'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Main data table
        st.subheader("Energy Sector CVEs (Sorted by Priority 1 First, then by EPSS)")
        display_cols = ['cve_id', 'description', 'cvss_score', 'epss_score', 'priority', 'in_kev']
        if 'matched_keywords' in df.columns:
            display_cols = ['cve_id', 'description', 'matched_keywords', 'cvss_score', 'epss_score', 'priority', 'in_kev']
        
        available_cols = [col for col in display_cols if col in df.columns]
        
        if 'in_kev' in df.columns:
            df['in_kev_display'] = df['in_kev'].map({1: '✅ Yes', 0: '❌ No'})
            if 'in_kev_display' not in available_cols:
                display_cols = [c if c != 'in_kev' else 'in_kev_display' for c in display_cols]
        
        st.dataframe(
            df[display_cols].head(500),
            use_container_width=True,
            height=500
        )
    else:
        st.info("No energy CVEs found in current dataset.")
        st.write(f"**{len(ENERGY_KEYWORDS)} energy keywords being used:**")
        for kw in sorted(ENERGY_KEYWORDS):
            st.markdown(f"- `{kw}`")
else:
    st.warning("No data available. Run updater first.")