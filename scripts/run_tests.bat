#!/usr/bin/env bash
# @title Lemonade Nexus Test Runner
# @description Runs all tests with coverage and generates reports.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_DIR="apps/LemonadeNexus"
COVERAGE_DIR="coverage"
REPORT_DIR="test_reports"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Lemonade Nexus Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Navigate to app directory
cd "$APP_DIR" || exit 1

# Clean previous results
echo -e "${YELLOW}Cleaning previous test artifacts...${NC}"
rm -rf "$COVERAGE_DIR" "$REPORT_DIR"
mkdir -p "$COVERAGE_DIR" "$REPORT_DIR"

# Get Flutter version
echo -e "${YELLOW}Flutter version:${NC}"
flutter --version
echo ""

# Fetch dependencies
echo -e "${YELLOW}Fetching dependencies...${NC}"
flutter pub get
echo ""

# Run tests
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Running Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run tests for a category
run_tests() {
    local category=$1
    local test_path=$2

    echo -e "${YELLOW}Running $category tests...${NC}"

    # Run tests with coverage
    if flutter test --coverage --test-randomize-ordering-seed random "$test_path" > "$REPORT_DIR/${category}_output.txt" 2>&1; then
        echo -e "${GREEN}✓ $category tests passed${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ $category tests failed${NC}"
        ((FAILED_TESTS++))
        cat "$REPORT_DIR/${category}_output.txt"
    fi

    ((TOTAL_TESTS++))
}

# Run FFI binding tests
run_tests "FFI Bindings" "test/ffi/"

# Run unit tests
run_tests "Unit Tests" "test/unit/"

# Run widget tests
run_tests "Widget Tests" "test/widget/"

# Run integration tests
run_tests "Integration Tests" "test/integration/"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Total test categories: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

# Generate coverage report
echo -e "${YELLOW}Generating coverage report...${NC}"

# Check if coverage files exist
if ls coverage/lcov*.info 1> /dev/null 2>&1; then
    # Combine coverage files
    lcov -o coverage/combined.info \
        $(ls coverage/lcov*.info | tr '\n' ' ' | sed 's/^/ -a /') 2>/dev/null || true

    # Generate HTML report
    genhtml -o coverage/html coverage/combined.info 2>/dev/null || true

    echo -e "${GREEN}Coverage report generated at: coverage/html/index.html${NC}"
else
    echo -e "${YELLOW}No coverage files generated${NC}"
fi

# Generate JUnit XML report
echo -e "${YELLOW}Generating JUnit XML report...${NC}"

# Create summary file
cat > "$REPORT_DIR/test_summary.txt" << EOF
Lemonade Nexus Test Summary
===========================
Date: $(date)
Flutter Version: $(flutter --version --short 2>/dev/null || echo "Unknown")

Test Results:
-------------
Total Categories: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "N/A")%

Test Categories:
----------------
EOF

# Append individual test results
for f in "$REPORT_DIR"/*_output.txt; do
    if [ -f "$f" ]; then
        category=$(basename "$f" _output.txt)
        echo "- $category" >> "$REPORT_DIR/test_summary.txt"
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Coverage Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Display coverage summary if available
if [ -f "coverage/combined.info" ]; then
    echo -e "${YELLOW}Coverage by module:${NC}"
    # Parse coverage info file for summary
    grep -E "^SF:" coverage/combined.info 2>/dev/null | head -20 || echo "No module data available"
else
    echo -e "${YELLOW}No coverage data available${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"

# Exit with appropriate code
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Some tests failed. Check $REPORT_DIR for details.${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
