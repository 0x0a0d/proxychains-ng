# Inline Config Test Suite

Test suite for the `inline-config` feature - CLI argument parsing and configuration override in proxychains-ng.

## Overview

The `inline-config` feature enables overriding configuration through command-line arguments. This test suite validates:

- **Parsing functions** - Proxy URLs, localnet specs, DNAT rules
- **Argument parsing** - All CLI options and flags
- **Edge cases** - NULL handling, boundary values, error conditions

## Test Files

```
tests/inline/
├── test_parsing_proxy.c          # Proxy URL parsing (4 tests)
├── test_parsing_localnet.c       # Localnet parsing (1 test)
├── test_parsing_dnat.c           # DNAT parsing (1 test)
├── test_argparse.c               # CLI argument parsing (16 tests)
└── test_edge_cases.c             # Edge cases & error handling (7 tests)
```

**Total: 29 tests**

## Running Tests

### Full clean build and test:
```bash
make clean && ./configure && make run-tests
```

### Run individual test:
```bash
./tests/inline/test_argparse
./tests/inline/test_parsing_proxy
# etc.
```

## Test Coverage

### test_parsing_proxy.c
- ✅ Basic socks5 URL parsing
- ✅ socks5h (remote DNS flag)
- ✅ Authentication (user:pass)
- ✅ Invalid protocol/missing port errors

### test_parsing_localnet.c
- ✅ IPv4 CIDR notation (/24)

### test_parsing_dnat.c
- ✅ IP-to-IP mapping (src-dst)

### test_argparse.c
- ✅ Quiet mode (-q)
- ✅ Config file (-f)
- ✅ Chain modes (strict, dynamic, random, round_robin)
- ✅ **Chain mode with inline length** (strict:3, dynamic:5, etc.)
- ✅ DNS modes (-d proxy/old/off/IP:PORT)
- ✅ Proxy list (-P, repeatable)
- ✅ Localnet (-n, repeatable)
- ✅ DNAT (--dnat, repeatable)
- ✅ Timeouts (-R, -T)
- ✅ Remote DNS subnet (-S)
- ✅ Combined options
- ✅ Help/version flags
- ✅ Missing argument errors

### test_edge_cases.c
- ✅ NULL pointer handling
- ✅ Empty string handling
- ✅ Whitespace handling
- ✅ Long strings (buffer overflow protection)
- ✅ Special characters
- ✅ Boundary values (ports 1-65535, CIDR /0-/32, /128)
- ✅ Malformed inputs

## Test Infrastructure

Tests use a simple shell script runner (`tools/tests.sh`) that:
1. Compiles each test file linking against source `.o` files
2. Runs each test executable
3. Reports pass/fail status

No complex test framework required - just simple C with `assert()`.

## Test Style

```c
#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");

void test_something() {
    TEST_START("test_name");
    
    // Setup
    cli_options opts;
    char *argv[] = {"proxychains4", "-q", "curl", "example.com"};
    
    // Execute
    int result = parse_arguments(4, argv, &opts, &start_argv);
    
    // Assert
    assert(result == 0);
    assert(opts.has_quiet == 1);
    
    TEST_PASS();
}
```

## Expected Output

When all tests pass:

```
===================================
Building inline-config test suite
===================================
Compiling tests...
===================================
Running inline-config test suite
===================================

=== Proxy URL Parsing Tests ===
Running: parse_socks5_basic... PASS
Running: parse_socks5h... PASS
...
✓ All proxy parsing tests passed!
✓ test_parsing_proxy passed

... (continues for all test suites)

===================================
✓ All test suites passed!
===================================
```

## Notes

- Tests link against object files from `src/` (parsing.o, argparse.o, common.o)
- Exit code 0 = all tests passed, non-zero = test failure
- Each test file can be run independently for debugging
- Tests follow the same simple style as existing proxychains-ng tests

## Adding More Tests

To add a new test case to an existing file:

1. Add a test function following the naming pattern `test_*`
2. Use `TEST_START()` and `TEST_PASS()` macros
3. Add assertions for your checks
4. Call the new test function in `main()`

Example:
```c
void test_my_new_feature() {
    TEST_START("my_new_feature");
    
    // Your test code here
    assert(something == expected);
    
    TEST_PASS();
}

int main() {
    // ... existing tests ...
    test_my_new_feature();  // Add this line
    return 0;
}
```
