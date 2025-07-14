# wolfHSM Static Analysis Tools

This directory contains static analysis tools and configurations for the wolfHSM project.

## Tools

### cppcheck
- **Script**: `run_cppcheck.sh`
- **Config**: `cppcheck-suppressions.txt`

### clang-tidy
- **Script**: `run_clang_tidy.sh`
- **Config**: `.clang-tidy`, `clang-tidy-suppressions.txt`

## Usage

### Running cppcheck
```bash
cd tools/static-analysis
./run_cppcheck.sh
```

### Running clang-tidy
```bash
cd tools/static-analysis
./run_clang_tidy.sh
```

Both tools will:
- Analyze source code in `src/` and `wolfhsm/` directories
- Generate reports in the `reports/` directory
- Exit with non-zero status if issues are found

## CI Integration

Both tools are designed to be integrated into the `.github/static-analysis.yml` CI job

## Configuration

### cppcheck

- Suppressions are managed in `cppcheck-suppressions.txt`
- Inline suppressions can be added to code with : `/* cppcheck-suppress warningId */`

### clang-tidy
- Checks are configured in `.clang-tidy`
- Inline suppressions can be added to code with : `/* NOLINT(check-name) */` or `/* NOLINTNEXTLINE(check-name) */`

## Requirements

- **cppcheck**: Install via package manager (`apt install cppcheck` on Ubuntu)
- **clang-tidy**: Part of LLVM/Clang toolchain (`apt install clang-tidy` on Ubuntu)

## Advanced Usage

### Environment Variables

The clang-tidy script supports environment variable overrides:

```bash
# Disable specific checks
CLANG_TIDY_ARGS="-checks=-readability-*" ./run_clang_tidy.sh

# Run only security checks
CLANG_TIDY_ARGS="-checks=-*,cert-*,clang-analyzer-security.*" ./run_clang_tidy.sh
```

