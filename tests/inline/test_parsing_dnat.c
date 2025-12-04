/***************************************************************************
 * test_parsing_dnat.c - Test DNAT parsing
 ***************************************************************************/

#include "../../src/parsing.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");

void test_parse_ip_only() {
  TEST_START("parse_ip_only");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1-2.2.2.2", &out);
  assert(result == 1);
  TEST_PASS();
}

void test_parse_src_with_port() {
  TEST_START("parse_src_with_port");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1:80-2.2.2.2", &out);
  assert(result == 1);
  assert(out.orig_port == 80);
  assert(out.new_port == 0);
  TEST_PASS();
}

void test_parse_dst_with_port() {
  TEST_START("parse_dst_with_port");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1-2.2.2.2:443", &out);
  assert(result == 1);
  assert(out.orig_port == 0);
  assert(out.new_port == 443);
  TEST_PASS();
}

void test_parse_both_with_ports() {
  TEST_START("parse_both_with_ports");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1:1-2.2.2.2:65535", &out);
  assert(result == 1);
  assert(out.orig_port == 1);
  assert(out.new_port == 65535);
  TEST_PASS();
}

void test_parse_missing_dash() {
  TEST_START("parse_missing_dash");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1", &out);
  assert(result == 0);
  TEST_PASS();
}

void test_parse_invalid_ip() {
  TEST_START("parse_invalid_ip");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.256-2.2.2.2", &out);
  assert(result == 0);
  TEST_PASS();
}

void test_parse_whitespace_fails() {
  TEST_START("parse_whitespace_fails");
  dnat_arg out;
  int result = parse_dnat_entry("1.1.1.1 - 2.2.2.2", &out);
  assert(result == 0);
  TEST_PASS();
}

void test_parse_ipv6_not_supported() {
  TEST_START("parse_ipv6_not_supported");
  dnat_arg out;
  int result = parse_dnat_entry("::1-::2", &out);
  assert(result == 0);
  TEST_PASS();
}

int main() {
  printf("=== DNAT Parsing Tests ===\n");
  test_parse_ip_only();
  test_parse_src_with_port();
  test_parse_dst_with_port();
  test_parse_both_with_ports();
  test_parse_missing_dash();
  test_parse_invalid_ip();
  test_parse_whitespace_fails();
  test_parse_ipv6_not_supported();
  printf("\n✓ All DNAT parsing tests passed!\n");
  return 0;
}
