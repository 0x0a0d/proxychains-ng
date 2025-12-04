/***************************************************************************
 * test_parsing_localnet.c - Test localnet parsing
 ***************************************************************************/

#include "../../src/parsing.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");

void test_parse_ipv4_cidr() {
  TEST_START("parse_ipv4_cidr");
  localaddr_arg out;
  int result = parse_localnet_entry("192.168.0.0/24", &out);
  assert(result == 1);
  TEST_PASS();
}

void test_parse_ipv4_mask() {
  TEST_START("parse_ipv4_mask");
  localaddr_arg out;
  int result = parse_localnet_entry("10.0.0.0/255.0.0.0", &out);
  assert(result == 1);
  assert(out.family == AF_INET);
  struct in_addr expected_mask;
  int rc = inet_pton(AF_INET, "255.0.0.0", &expected_mask);
  assert(rc == 1);
  assert(out.in_mask.s_addr == expected_mask.s_addr);
  TEST_PASS();
}

void test_parse_ipv4_with_port() {
  TEST_START("parse_ipv4_with_port");
  localaddr_arg out;
  int result = parse_localnet_entry("192.168.1.1:8080/32", &out);
  assert(result == 1);
  assert(out.family == AF_INET);
  assert(out.port == 8080);
  TEST_PASS();
}

void test_parse_ipv6_cidr() {
  TEST_START("parse_ipv6_cidr");
  localaddr_arg out;
  int result = parse_localnet_entry("2001:db8::/32", &out);
  assert(result == 1);
  assert(out.family == AF_INET6);
  assert(out.in6_prefix == 32);
  TEST_PASS();
}

void test_parse_ipv6_with_port() {
  TEST_START("parse_ipv6_with_port");
  localaddr_arg out;
  int result = parse_localnet_entry("[::1]:8080/128", &out);
  assert(result == 1);
  assert(out.family == AF_INET6);
  assert(out.port == 8080);
  assert(out.in6_prefix == 128);
  TEST_PASS();
}

void test_parse_invalid_prefix() {
  TEST_START("parse_invalid_prefix");
  localaddr_arg out;
  int result = parse_localnet_entry("192.168.0.0/33", &out);
  assert(result == 0);
  TEST_PASS();
}

void test_parse_non_numeric_port() {
  TEST_START("parse_non_numeric_port");
  localaddr_arg out;
  int result = parse_localnet_entry("192.168.0.0:abc/24", &out);
  assert(result == 0);
  TEST_PASS();
}

int main() {
  printf("=== Localnet Parsing Tests ===\n");
  test_parse_ipv4_cidr();
  test_parse_ipv4_mask();
  test_parse_ipv4_with_port();
  test_parse_ipv6_cidr();
  test_parse_ipv6_with_port();
  test_parse_invalid_prefix();
  test_parse_non_numeric_port();
  printf("\n✓ All localnet parsing tests passed!\n");
  return 0;
}
