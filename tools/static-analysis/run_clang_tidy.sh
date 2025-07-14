#!/bin/bash

# Script to run clang-tidy on wolfHSM source code
# Analyzes src/* and wolfhsm/* directories (excludes test and benchmarks)
#
# Environment variables:
#   CLANG_TIDY_ARGS - Override default clang-tidy arguments
#   Example: CLANG_TIDY_ARGS="-checks=-readability-*" ./run_clang_tidy.sh

# Exit on error
set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Create reports directory
REPORTS_DIR="$PROJECT_ROOT/reports"
mkdir -p "$REPORTS_DIR"

echo "Running clang-tidy static analysis on wolfHSM..."
echo "Project root: $PROJECT_ROOT"
echo "Reports will be saved to: $REPORTS_DIR"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check if clang-tidy is installed
if ! command -v clang-tidy &> /dev/null; then
    echo -e "${RED}Error: clang-tidy not found. Please install clang-tidy.${NC}"
    exit 1
fi

# Check if run-clang-tidy is available (comes with clang-tidy)
RUN_CLANG_TIDY=""
if command -v run-clang-tidy &> /dev/null; then
    RUN_CLANG_TIDY="run-clang-tidy"
elif command -v run-clang-tidy.py &> /dev/null; then
    RUN_CLANG_TIDY="run-clang-tidy.py"
else
    echo -e "${YELLOW}Warning: run-clang-tidy not found. Using fallback method.${NC}"
fi

# Find all C source and header files in src/ and wolfhsm/
echo "Finding source files to analyze..."
SOURCE_FILES=$(find src wolfhsm -name "*.c" -o -name "*.h" | grep -v -E "(test|benchmark)" | sort)
NUM_FILES=$(echo "$SOURCE_FILES" | wc -l)
echo "Found $NUM_FILES files to analyze"
echo ""

# Copy .clang-tidy configuration to project root (clang-tidy looks for it there)
cp "$SCRIPT_DIR/.clang-tidy" "$PROJECT_ROOT/.clang-tidy"

# Generate compilation database if it doesn't exist
# This is a simple compilation database for C files
if [ ! -f "$PROJECT_ROOT/compile_commands.json" ]; then
    echo "Generating compilation database..."
    cat > "$PROJECT_ROOT/compile_commands.json" << EOF
[
EOF

    FIRST=1
    for file in $SOURCE_FILES; do
        if [[ "$file" == *.c ]]; then
            if [ $FIRST -eq 0 ]; then
                echo "," >> "$PROJECT_ROOT/compile_commands.json"
            fi
            FIRST=0
            cat >> "$PROJECT_ROOT/compile_commands.json" << EOF
  {
    "directory": "$PROJECT_ROOT",
    "command": "gcc -c -std=c99 -Wall -I$PROJECT_ROOT -I$PROJECT_ROOT/wolfhsm -I$PROJECT_ROOT/../wolfssl -DWOLFHSM_CFG_NO_CRYPTO $file -o ${file%.c}.o",
    "file": "$file"
  }
EOF
        fi
    done

    echo "" >> "$PROJECT_ROOT/compile_commands.json"
    echo "]" >> "$PROJECT_ROOT/compile_commands.json"
fi

# Allow override of clang-tidy arguments via environment variable
if [ -z "$CLANG_TIDY_ARGS" ]; then
    CLANG_TIDY_ARGS="-header-filter=^(src/|wolfhsm/).*\.(h)$"
fi

# Run clang-tidy and capture output
echo "Running clang-tidy analysis..."
CLANG_TIDY_OUTPUT="$REPORTS_DIR/clang_tidy_output.txt"
CLANG_TIDY_SUMMARY="$REPORTS_DIR/clang_tidy_summary.txt"

if [ -n "$RUN_CLANG_TIDY" ]; then
    # Use run-clang-tidy for parallel execution
    $RUN_CLANG_TIDY -p "$PROJECT_ROOT" $CLANG_TIDY_ARGS -quiet \
        $SOURCE_FILES 2>&1 | tee "$CLANG_TIDY_OUTPUT"
else
    # Fallback: run clang-tidy on each file
    > "$CLANG_TIDY_OUTPUT"
    for file in $SOURCE_FILES; do
        if [[ "$file" == *.c ]]; then
            echo "Analyzing $file..." >> "$CLANG_TIDY_OUTPUT"
            clang-tidy -p "$PROJECT_ROOT" $CLANG_TIDY_ARGS "$file" 2>&1 >> "$CLANG_TIDY_OUTPUT" || true
        fi
    done
fi

# Parse output and create summary
echo ""
echo "Generating summary report..."

# Count different types of issues
ERRORS=0
WARNINGS=0
NOTES=0

while IFS= read -r line; do
    if [[ "$line" =~ error: ]]; then
        ((ERRORS++))
    elif [[ "$line" =~ warning: ]]; then
        ((WARNINGS++))
    elif [[ "$line" =~ note: ]]; then
        ((NOTES++))
    fi
done < "$CLANG_TIDY_OUTPUT"

# Generate summary report
cat > "$CLANG_TIDY_SUMMARY" << EOF
clang-tidy Static Analysis Summary
==================================
Date: $(date)
Files analyzed: $NUM_FILES

Results:
--------
Errors:   $ERRORS
Warnings: $WARNINGS
Notes:    $NOTES

Total issues: $((ERRORS + WARNINGS))

Detailed output: $CLANG_TIDY_OUTPUT
EOF

# Display summary
echo ""
cat "$CLANG_TIDY_SUMMARY"

# Generate YAML report for CI integration (if clang-tidy supports it)
if clang-tidy --version | grep -q "version 1[0-9]"; then
    echo ""
    echo "Generating YAML report..."
    YAML_OUTPUT="$REPORTS_DIR/clang_tidy.yaml"
    > "$YAML_OUTPUT"
    for file in $SOURCE_FILES; do
        if [[ "$file" == *.c ]]; then
            clang-tidy -p "$PROJECT_ROOT" --export-fixes=- "$file" 2>/dev/null >> "$YAML_OUTPUT" || true
        fi
    done
fi

# Clean up temporary files
rm -f "$PROJECT_ROOT/.clang-tidy"
if [ -f "$PROJECT_ROOT/compile_commands.json.generated" ]; then
    rm -f "$PROJECT_ROOT/compile_commands.json"
fi

# Exit with error if issues found
echo ""
if [ $ERRORS -gt 0 ] || [ $WARNINGS -gt 0 ]; then
    echo -e "${RED}Static analysis found $((ERRORS + WARNINGS)) issue(s)!${NC}"
    echo -e "${RED}Errors: $ERRORS, Warnings: $WARNINGS${NC}"
    exit 1
else
    echo -e "${GREEN}Static analysis completed successfully with no issues!${NC}"
    exit 0
fi