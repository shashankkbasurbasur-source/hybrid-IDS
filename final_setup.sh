#!/bin/bash

# HYBRID IDS FINAL SETUP SCRIPT
# Completes the entire project setup

set -e

echo "════════════════════════════════════════════════════════════════════════════════"
echo "HYBRID IDS - FINAL SETUP AND VALIDATION"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}Step 1: Verify Python environment${NC}"
python3 --version
echo "✓ Python OK"
echo ""

echo -e "${BLUE}Step 2: Install/verify dependencies${NC}"
pip install --upgrade pip > /dev/null 2>&1
pip install -q scapy numpy pandas scikit-learn fastapi uvicorn streamlit requests pydantic
echo "✓ Dependencies OK"
echo ""

echo -e "${BLUE}Step 3: Verify project structure${NC}"
mkdir -p backend/{core,detection/ml,features,api,scenarios,threats,storage,alerts,parsing,dashboard,tests}
mkdir -p models logs
mkdir -p ml_pipeline

echo "✓ Project structure verified"
echo ""

echo -e "${BLUE}Step 4: Create missing __init__.py files${NC}"
for dir in backend backend/core backend/detection backend/detection/ml backend/features \
           backend/api backend/scenarios backend/threats backend/storage backend/alerts \
           backend/parsing backend/dashboard backend/tests backend/ingestions; do
    if [ -d "$dir" ]; then
        touch "$dir/__init__.py" 2>/dev/null || true
    fi
done
echo "✓ Init files created"
echo ""

echo -e "${BLUE}Step 5: Verify trained models${NC}"
if [ ! -f "models/random_forest_model.pkl" ]; then
    echo -e "${YELLOW}⚠ NIDS model not found. Run training first:${NC}"
    echo "   python ml_pipeline/train_random_forest.py"
    exit 1
fi
echo "✓ NIDS model found"

if [ ! -f "models/hids_model.pkl" ]; then
    echo -e "${YELLOW}⚠ HIDS model not found. Run training first:${NC}"
    echo "   python ml_pipeline/train_hids.py"
    exit 1
fi
echo "✓ HIDS model found"
echo ""

echo -e "${BLUE}Step 6: Run validation tests${NC}"
python3 backend/tests/validate_full_pipeline.py

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Validation failed${NC}"
    exit 1
fi
echo ""

echo -e "${BLUE}Step 7: Initialize alert storage${NC}"
rm -f logs/alerts.db logs/alerts.jsonl
python3 -c "from backend.storage.db_store import alert_store; alert_store.stats()" > /dev/null
echo "✓ Alert storage initialized"
echo ""

echo "════════════════════════════════════════════════════════════════════════════════"
echo -e "${GREEN}✓ SETUP COMPLETE${NC}"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "START THE SYSTEM:"
echo ""
echo "  Terminal 1 (API):"
echo "    python backend/app.py"
echo ""
echo "  Terminal 2 (Dashboard):"
echo "    streamlit run backend/dashboard/app_phase2.py"
echo ""
echo "  Then open:"
echo "    http://127.0.0.1:8501"
echo ""
echo "TEST SCENARIOS:"
echo "  - Go to 'Test Scenarios' tab"
echo "  - Select an attack scenario"
echo "  - Click 'Run Scenario Test'"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"