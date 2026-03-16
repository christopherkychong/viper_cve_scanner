"""
Main VIPER Dashboard Application
Serves as the entry point for the Streamlit web interface.

This module provides:
- Sidebar with Australian timezone display
- Update schedule information
- Navigation to sector-specific pages
- High-level metrics about the system
"""

import streamlit as st
from datetime import datetime
import pytz

# Configure page settings for the entire app
st.set_page_config(
    page_title="VIPER - Vulnerability Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Display current Australian time in the sidebar
# All times in the app are shown in AEDT/AEST for Australian users
australia_tz = pytz.timezone('Australia/Sydney')
aus_now = datetime.now(pytz.utc).astimezone(australia_tz)

st.sidebar.title("🛡️ VIPER")
st.sidebar.caption(f"Australian time: {aus_now.strftime('%Y-%m-%d %H:%M')}")

# Display update schedule information
st.sidebar.markdown("---")
st.sidebar.markdown("### 📅 Update Schedule")
st.sidebar.markdown("📊 EPSS: Daily 10pm AEDT")
st.sidebar.markdown("⚡ Energy: Tuesday 1am AEDT")
st.sidebar.markdown("🏥 Healthcare: 2nd of month 2am AEDT")

# Main page content
st.title("🛡️ VIPER - Vulnerability Intelligence Platform")
st.markdown("---")

# Display high-level metrics about the system
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total CVEs Monitored", "1,000+", "Daily EPSS updates")
with col2:
    st.metric("Active Sectors", "2", "Healthcare, Energy")
with col3:
    st.metric("Data Sources", "3", "NVD, EPSS, CISA KEV")

st.markdown("---")
st.markdown("### 📈 Quick Stats")
st.info("Select a sector from the left sidebar to begin analysis")