"""
VIPER - Vulnerability Intelligence Platform
Main entry point that launches the Streamlit dashboard.

This script handles:
- Adding the project root to Python path for imports
- Checking if virtual environment is activated
- Gracefully handling Ctrl+C shutdown
- Launching the Streamlit application
"""

import sys
import subprocess
from pathlib import Path

# Add the project root directory to Python path
# This ensures imports like 'src.utils' work correctly
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    print("🚀 Launching VIPER Dashboard...")
    print("Press Ctrl+C to stop")
    
    # Check if streamlit is installed in the current environment
    # This helps users who forget to activate their virtual environment
    try:
        import streamlit
    except ImportError:
        print("\n" + "="*60)
        print("❌ ERROR: Streamlit is not installed in the current Python environment")
        print("="*60)
        print("\n📌 The virtual environment needs to be activated first!")
        print("\n👉 Run this command:")
        print("   venv\\Scripts\\activate")
        print("\nThen try again:")
        print("   python main.py")
        sys.exit(1)
    
    # Run streamlit as a module to ensure proper Python path resolution
    cmd = [sys.executable, "-m", "streamlit", "hello"]
    
    try:
        # Launch the dashboard and wait for it to complete
        process = subprocess.Popen(cmd)
        process.wait()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully - stop the dashboard cleanly
        print("\n🛑 Stopping VIPER...")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        print("✅ VIPER stopped")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)