#!/bin/bash
# Setup script for Bluetooth Attack Detection System
# This script installs all required dependencies

set -e  # Exit on error

echo "=========================================="
echo "🛡️ BT-Protector Setup Script"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Python 3 is required but not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found${NC}"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip3 install --upgrade pip --quiet
echo -e "${GREEN}✓ pip upgraded${NC}"
echo ""

# Install core requirements
echo "Installing core requirements..."
pip3 install -r requirements.txt --quiet
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All requirements installed successfully${NC}"
else
    echo -e "${RED}✗ Failed to install requirements${NC}"
    exit 1
fi
echo ""

# Verify installation
echo "Verifying installation..."
python3 -c "import streamlit; import plotly; import pandas; import snowflake.connector; import sqlalchemy"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All packages verified${NC}"
else
    echo -e "${YELLOW}⚠ Some packages may not be fully verified${NC}"
fi
echo ""

# Check for Bluetooth hardware (optional)
echo "Checking Bluetooth support..."
if command -v hciconfig &> /dev/null; then
    echo -e "${GREEN}✓ Bluetooth tools found${NC}"
    hciconfig 2>/dev/null || echo "  (No Bluetooth interface detected)"
else
    echo -e "${YELLOW}⚠ Bluetooth tools not found (required for actual Bluetooth scanning)${NC}"
    echo "  Install with: sudo apt-get install bluez bluez-tools"
fi
echo ""

echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To run the web interface:"
echo "  streamlit run app.py"
echo ""
echo "To set up Snowflake:"
echo "  1. Run snowflake_schema.sql in Snowflake"
echo "  2. Set environment variables or update config.toml"
echo ""
echo "For more information, see README.md"
echo ""

