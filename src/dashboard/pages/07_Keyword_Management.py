"""
Keyword Management Page
View, add, and manage ALL sector keywords through the UI.

This page provides a complete interface for keyword management:
- View all healthcare and energy keywords by category
- Add, edit, or delete keywords through simple text areas
- Automatic backups before each save
- Restore from any previous backup
- Delete old backups with confirmation
- All keywords stored in JSON file
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import streamlit as st
import pandas as pd
from datetime import datetime
import shutil
import json
import os

st.set_page_config(page_title="Keyword Management", layout="wide")
st.title("🔑 Keyword Management")

# File paths for keyword storage
KEYWORDS_FILE = Path("src/utils/keywords.json")
BACKUP_DIR = Path("data/keyword_backups")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

# Initialize session state for delete confirmation and UI refresh
if 'delete_confirmation' not in st.session_state:
    st.session_state.delete_confirmation = None
if 'file_to_delete' not in st.session_state:
    st.session_state.file_to_delete = None
if 'restore_trigger' not in st.session_state:
    st.session_state.restore_trigger = False
if 'force_reload' not in st.session_state:
    st.session_state.force_reload = 0

# Default keywords (fallback if file reading fails)
DEFAULT_KEYWORDS = {
    'healthcare': {
        'medical_devices': ['mri', 'pacemaker', 'ventilator'],
        'healthcare_it': ['ehr', 'emr', 'dicom'],
        'vendors': ['philips', 'medtronic', 'ge'],
        'clinical_context': ['patient', 'hospital', 'clinical']
    },
    'energy': {
        'ot_ics': ['scada', 'plc', 'ics'],
        'infrastructure': ['grid', 'substation', 'pipeline'],
        'vendors': ['siemens', 'schneider', 'rockwell'],
        'components': ['hmi', 'rtu', 'controller']
    }
}

def load_all_keywords():
    """
    Load keywords from the JSON file.
    
    Returns:
        Dictionary with complete keyword structure
        Falls back to defaults if file is missing or corrupted
    """
    try:
        if not KEYWORDS_FILE.exists():
            st.warning("Keywords file not found. Using defaults.")
            return DEFAULT_KEYWORDS.copy()
        
        with open(KEYWORDS_FILE, 'r') as f:
            keywords = json.load(f)
        
        return keywords
        
    except json.JSONDecodeError as e:
        st.error(f"Error parsing keywords JSON: {e}")
        return DEFAULT_KEYWORDS.copy()
    except Exception as e:
        st.error(f"Error loading keywords: {e}")
        return DEFAULT_KEYWORDS.copy()

def save_all_keywords(keywords_dict):
    """
    Save keywords to JSON file with automatic backup.
    
    Args:
        keywords_dict: Complete keyword structure to save
        
    Returns:
        Tuple of (success boolean, message string)
    """
    try:
        # Create timestamped backup before saving
        backup_file = BACKUP_DIR / f"keywords_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if KEYWORDS_FILE.exists():
            shutil.copy(KEYWORDS_FILE, backup_file)
        
        # Save to JSON file
        with open(KEYWORDS_FILE, 'w') as f:
            json.dump(keywords_dict, f, indent=2)
        
        return True, f"✅ Keywords saved! Backup: {backup_file.name}"
        
    except Exception as e:
        return False, f"❌ Error saving: {e}"

def restore_from_backup(backup_file):
    """
    Restore keywords from a selected backup file.
    
    Args:
        backup_file: Path to the backup file to restore
        
    Returns:
        Tuple of (success boolean, message string)
    """
    try:
        # Create a backup of current file before restore (safety net)
        current_backup = BACKUP_DIR / f"pre_restore_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if KEYWORDS_FILE.exists():
            shutil.copy(KEYWORDS_FILE, current_backup)
        
        # Copy backup file to active location
        shutil.copy(backup_file, KEYWORDS_FILE)
        
        return True, f"✅ Restored from: {backup_file.name}\nCurrent file backed up as: {current_backup.name}"
    except Exception as e:
        return False, f"❌ Restore failed: {e}"

def delete_backup(backup_file):
    """
    Delete a backup file.
    
    Args:
        backup_file: Path to the backup file to delete
        
    Returns:
        Tuple of (success boolean, message string)
    """
    try:
        os.remove(backup_file)
        return True, f"✅ Deleted: {backup_file.name}"
    except Exception as e:
        return False, f"❌ Delete failed: {e}"

# Main UI - Instructions
st.info("""
    **How this works:**
    - All keyword categories for Healthcare and Energy are shown below
    - Keywords are stored in a JSON file
    - Changes take effect immediately after saving
    - A backup is created automatically before each save
""")

# Load current keywords
keywords_data = load_all_keywords()

# Create tabs for Healthcare and Energy
hc_tab, en_tab = st.tabs(["🏥 Healthcare Keywords", "⚡ Energy Keywords"])

with hc_tab:
    st.subheader("Healthcare Keyword Categories")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Medical Devices**")
        hc_md = st.text_area(
            "One per line",
            value="\n".join(keywords_data['healthcare']['medical_devices']),
            height=150,
            key=f"hc_md_{st.session_state.force_reload}"
        )
        
        st.markdown("**Vendors**")
        hc_vend = st.text_area(
            "One per line",
            value="\n".join(keywords_data['healthcare']['vendors']),
            height=150,
            key=f"hc_vend_{st.session_state.force_reload}"
        )
    
    with col2:
        st.markdown("**Healthcare IT**")
        hc_it = st.text_area(
            "One per line",
            value="\n".join(keywords_data['healthcare']['healthcare_it']),
            height=150,
            key=f"hc_it_{st.session_state.force_reload}"
        )
        
        st.markdown("**Clinical Context**")
        hc_cc = st.text_area(
            "One per line",
            value="\n".join(keywords_data['healthcare']['clinical_context']),
            height=150,
            key=f"hc_cc_{st.session_state.force_reload}"
        )
    
    # Parse inputs into lists
    new_hc_md = [k.strip() for k in hc_md.split("\n") if k.strip()]
    new_hc_it = [k.strip() for k in hc_it.split("\n") if k.strip()]
    new_hc_vend = [k.strip() for k in hc_vend.split("\n") if k.strip()]
    new_hc_cc = [k.strip() for k in hc_cc.split("\n") if k.strip()]

with en_tab:
    st.subheader("Energy Keyword Categories")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**OT/ICS**")
        en_ot = st.text_area(
            "One per line",
            value="\n".join(keywords_data['energy']['ot_ics']),
            height=150,
            key=f"en_ot_{st.session_state.force_reload}"
        )
        
        st.markdown("**Vendors**")
        en_vend = st.text_area(
            "One per line",
            value="\n".join(keywords_data['energy']['vendors']),
            height=150,
            key=f"en_vend_{st.session_state.force_reload}"
        )
    
    with col2:
        st.markdown("**Infrastructure**")
        en_inf = st.text_area(
            "One per line",
            value="\n".join(keywords_data['energy']['infrastructure']),
            height=150,
            key=f"en_inf_{st.session_state.force_reload}"
        )
        
        st.markdown("**Components**")
        en_comp = st.text_area(
            "One per line",
            value="\n".join(keywords_data['energy']['components']),
            height=150,
            key=f"en_comp_{st.session_state.force_reload}"
        )
    
    # Parse inputs into lists
    new_en_ot = [k.strip() for k in en_ot.split("\n") if k.strip()]
    new_en_inf = [k.strip() for k in en_inf.split("\n") if k.strip()]
    new_en_vend = [k.strip() for k in en_vend.split("\n") if k.strip()]
    new_en_comp = [k.strip() for k in en_comp.split("\n") if k.strip()]

# Save button
st.markdown("---")
col1, col2 = st.columns([1, 3])

with col1:
    if st.button("💾 Save All Keywords", type="primary", use_container_width=True):
        # Build updated keyword structure from user inputs
        updated_keywords = {
            'healthcare': {
                'medical_devices': new_hc_md,
                'healthcare_it': new_hc_it,
                'vendors': new_hc_vend,
                'clinical_context': new_hc_cc
            },
            'energy': {
                'ot_ics': new_en_ot,
                'infrastructure': new_en_inf,
                'vendors': new_en_vend,
                'components': new_en_comp
            }
        }
        success, message = save_all_keywords(updated_keywords)
        if success:
            st.success(message)
            st.balloons()
            st.session_state.force_reload += 1  # Force UI refresh
            st.rerun()
        else:
            st.error(message)

with col2:
    st.caption("All categories will be saved. Backups are stored in data/keyword_backups/")

# Display current keyword counts by category
st.markdown("---")
st.subheader("📊 Current Keyword Counts")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**🏥 Healthcare**")
    st.markdown(f"- Medical Devices: {len(keywords_data['healthcare']['medical_devices'])}")
    st.markdown(f"- Healthcare IT: {len(keywords_data['healthcare']['healthcare_it'])}")
    st.markdown(f"- Vendors: {len(keywords_data['healthcare']['vendors'])}")
    st.markdown(f"- Clinical Context: {len(keywords_data['healthcare']['clinical_context'])}")

with col2:
    st.markdown("**⚡ Energy**")
    st.markdown(f"- OT/ICS: {len(keywords_data['energy']['ot_ics'])}")
    st.markdown(f"- Infrastructure: {len(keywords_data['energy']['infrastructure'])}")
    st.markdown(f"- Vendors: {len(keywords_data['energy']['vendors'])}")
    st.markdown(f"- Components: {len(keywords_data['energy']['components'])}")

# Backup Management Section
st.markdown("---")
st.subheader("📋 Backup Management")

# Get all backup files (JSON backups only)
backup_files = sorted(BACKUP_DIR.glob("keywords_backup_*.json"), reverse=True)

if backup_files:
    # Create a list of backup files with readable names
    backup_options = []
    backup_file_map = {}
    
    for bf in backup_files:
        timestamp_str = bf.stem.replace("keywords_backup_", "")
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            display_name = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {bf.name}"
            backup_options.append(display_name)
            backup_file_map[display_name] = bf
        except:
            backup_options.append(bf.name)
            backup_file_map[bf.name] = bf
    
    # Backup selection dropdown
    selected_backup = st.selectbox(
        "Select a backup file to restore",
        options=backup_options,
        key=f"backup_selector_{st.session_state.force_reload}"
    )
    
    if selected_backup:
        selected_file = backup_file_map[selected_backup]
        file_size = selected_file.stat().st_size / 1024
        
        # Show backup details and action buttons
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            st.caption(f"Size: {file_size:.1f} KB")
        
        with col2:
            if st.button("🔄 Restore", use_container_width=True):
                success, message = restore_from_backup(selected_file)
                if success:
                    st.success(message)
                    st.session_state.force_reload += 1
                    st.rerun()
                else:
                    st.error(message)
        
        with col3:
            if st.button("🗑️ Delete", use_container_width=True):
                st.session_state.file_to_delete = selected_file
                st.session_state.delete_confirmation = True
                st.rerun()
    
    # Delete confirmation dialog
    if st.session_state.delete_confirmation and st.session_state.file_to_delete:
        st.warning(f"⚠️ Are you sure you want to delete: {st.session_state.file_to_delete.name}?")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Yes, Delete", type="primary"):
                success, message = delete_backup(st.session_state.file_to_delete)
                if success:
                    st.success(message)
                    st.session_state.delete_confirmation = False
                    st.session_state.file_to_delete = None
                    st.session_state.force_reload += 1
                    st.rerun()
                else:
                    st.error(message)
        
        with col2:
            if st.button("❌ No, Cancel"):
                st.session_state.delete_confirmation = False
                st.session_state.file_to_delete = None
                st.rerun()
    
    # Show backup history table
    st.markdown("### Backup History")
    backup_data = []
    for bf in backup_files[:10]:
        timestamp_str = bf.stem.replace("keywords_backup_", "")
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            backup_data.append({
                "Date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Filename": bf.name,
                "Size (KB)": f"{bf.stat().st_size / 1024:.1f}"
            })
        except:
            pass
    
    if backup_data:
        st.dataframe(pd.DataFrame(backup_data), use_container_width=True)
    
else:
    st.info("No backups yet. Save keywords to create your first backup.")