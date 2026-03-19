"""
Healthcare Sector Dashboard
Displays CVEs that are relevant to the healthcare industry.

This page filters vulnerabilities using healthcare-specific keywords and provides:
- Summary metrics for healthcare CVEs
- Device category analysis (Imaging, Patient Monitoring, etc.)
- List of matched keywords for each CVE
- Detailed table of healthcare vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
from src.utils.database_handler import DatabaseHandler

# Force reload keywords from file on every page load
import importlib
import src.utils.industry_filters
importlib.reload(src.utils.industry_filters)
from src.utils.industry_filters import industry_filter

st.set_page_config(page_title="Healthcare Sector", layout="wide")
st.title("🏥 Healthcare Sector Vulnerabilities")

# Initialize database connection
db = DatabaseHandler()
all_cves = db.get_all_cves(limit=1000)

def get_healthcare_keywords():
    """
    Extract all healthcare keywords from the industry filter.
    
    Returns:
        List of all healthcare-related keywords across all categories
    """
    try:
        if hasattr(industry_filter, 'keywords') and 'healthcare' in industry_filter.keywords:
            healthcare_keywords = []
            for category, keywords in industry_filter.keywords['healthcare'].items():
                healthcare_keywords.extend(keywords)
            return healthcare_keywords
        return []
    except Exception as e:
        st.error(f"Error loading healthcare keywords: {e}")
        return []

HEALTHCARE_KEYWORDS = get_healthcare_keywords()

if all_cves:
    # Filter CVEs that match healthcare keywords
    healthcare_cves = []
    matched_keywords = set()  # Track which keywords actually matched CVEs
    
    for cve in all_cves:
        desc = cve.get('description', '').lower()
        matched = []
        for kw in HEALTHCARE_KEYWORDS:
            if kw.lower() in desc:
                matched.append(kw)
                matched_keywords.add(kw)
        if matched:
            # Store the keywords that matched for display
            cve['matched_keywords'] = ', '.join(matched[:3])
            healthcare_cves.append(cve)
    
    if healthcare_cves:
        df = pd.DataFrame(healthcare_cves)
        
        # Display summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Healthcare CVEs", len(df))
        with col2:
            critical = len(df[df['priority'].str.contains('PRIORITY 1', na=False)])
            st.metric("Priority 1+1", critical)
        with col3:
            exploited = len(df[df['in_kev'] == 1])
            st.metric("Actively Exploited", exploited)
        with col4:
            high_epss = len(df[df['epss_score'] > 0.5])
            st.metric("High EPSS (>0.5)", high_epss)
        
        # Show keyword usage statistics
        with st.expander(f"📋 Current Healthcare Keywords ({len(HEALTHCARE_KEYWORDS)} total)"):
            col1, col2 = st.columns(2)
            
            if matched_keywords:
                with col1:
                    st.markdown("**✅ Keywords that matched CVEs:**")
                    for kw in sorted(matched_keywords):
                        st.markdown(f"- `{kw}`")
            
            with col2:
                st.markdown("**📋 All tracked keywords:**")
                for kw in sorted(HEALTHCARE_KEYWORDS):
                    st.markdown(f"- `{kw}`")
        
        st.markdown("---")
        
        # Device category analysis
        st.subheader("Healthcare Device Categories")
        
        def categorize_device(desc):
            """
            Categorize a CVE description into a device type based on keywords.
            
            Returns:
                String category: Imaging, Patient Monitoring, Therapeutic, Healthcare IT, or Other
            """
            desc_lower = desc.lower()
            if any(k in desc_lower for k in ['mri', 'ct', 'x-ray', 'imaging', 'ultrasound']):
                return "Imaging"
            elif any(k in desc_lower for k in ['monitor', 'telemetry', 'vital', 'patient monitor']):
                return "Patient Monitoring"
            elif any(k in desc_lower for k in ['ventilator', 'pump', 'infusion', 'dialysis']):
                return "Therapeutic"
            elif any(k in desc_lower for k in ['ehr', 'emr', 'record', 'dicom', 'pacs', 'hl7']):
                return "Healthcare IT"
            else:
                return "Other"
        
        if 'description' in df.columns:
            df['device_category'] = df['description'].apply(categorize_device)
            category_counts = df['device_category'].value_counts()
            
            if not category_counts.empty:
                fig = px.pie(
                    values=category_counts.values,
                    names=category_counts.index,
                    title="CVEs by Device Category"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Main data table with matched keywords
        st.subheader("Healthcare CVEs")
        display_cols = ['cve_id', 'description', 'cvss_score', 'epss_score', 'priority', 'in_kev']
        if 'matched_keywords' in df.columns:
            display_cols = ['cve_id', 'description', 'matched_keywords', 'cvss_score', 'epss_score', 'priority', 'in_kev']
        
        # Format boolean fields for display
        if 'in_kev' in df.columns:
            df['in_kev_display'] = df['in_kev'].map({1: '✅ Yes', 0: '❌ No'})
            display_cols = [c if c != 'in_kev' else 'in_kev_display' for c in display_cols]
        
        st.dataframe(
            df[display_cols].sort_values('epss_score', ascending=False),
            use_container_width=True,
            height=500
        )
    else:
        st.info("No healthcare CVEs found in current dataset.")
        st.write(f"**{len(HEALTHCARE_KEYWORDS)} healthcare keywords being used:**")
        for kw in sorted(HEALTHCARE_KEYWORDS):
            st.markdown(f"- `{kw}`")
else:
    st.warning("No data available. Run updater first.")