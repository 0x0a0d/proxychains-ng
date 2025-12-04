#!/bin/sh
# Test runner script for proxychains-ng inline-config tests

set -e

TESTS_DIR="$(dirname "$0")"
SRC_DIR="$TESTS_DIR/../../src"

echo "==================================="
echo "Building inline-config test suite"
echo "==================================="

# Compile each test
echo "Compiling tests..."

# Test parsing functions
cc $CPPFLAGS $CFLAGS -I$SRC_DIR -o $TESTS_DIR/test_parsing_proxy \
   $TESTS_DIR/test_parsing_proxy.c $SRC_DIR/parsing.o

cc $CPPFLAGS $CFLAGS -I$SRC_DIR -o $TESTS_DIR/test_parsing_localnet \
   $TESTS_DIR/test_parsing_localnet.c $SRC_DIR/parsing.o

cc $CPPFLAGS $CFLAGS -I$SRC_DIR -o $TESTS_DIR/test_parsing_dnat \
   $TESTS_DIR/test_parsing_dnat.c $SRC_DIR/parsing.o

# Test argparse
cc $CPPFLAGS $CFLAGS -I$SRC_DIR -o $TESTS_DIR/test_argparse \
   $TESTS_DIR/test_argparse.c $SRC_DIR/argparse.o $SRC_DIR/common.o

# Test edge cases
cc $CPPFLAGS $CFLAGS -I$SRC_DIR -o $TESTS_DIR/test_edge_cases \
   $TESTS_DIR/test_edge_cases.c $SRC_DIR/parsing.o

echo "==================================="
echo "Running inline-config test suite"
echo "==================================="

# Run tests
FAILED=0

run_test() {
	echo ""
	if $TESTS_DIR/$1; then
		echo "✓ $1 passed"
	else
		echo "✗ $1 failed"
		FAILED=$((FAILED + 1))
	fi
}

run_test test_parsing_proxy
run_test test_parsing_localnet
run_test test_parsing_dnat
run_test test_argparse
run_test test_edge_cases

echo ""
echo "==================================="
if [ $FAILED -eq 0 ]; then
	echo "✓ All test suites passed!"
	echo "==================================="
	exit 0
else
	echo "✗ $FAILED test suite(s) failed"
	echo "==================================="
	exit 1
fi
