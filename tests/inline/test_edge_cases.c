/***************************************************************************
 * test_edge_cases.c - Test edge cases and error handling
 ***************************************************************************/

#include "../../src/parsing.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");
#define MAX_TEST_STRING 4096

/* Test NULL pointer handling */
void test_null_pointers() {
  TEST_START("null_pointers");
  proxy_data_ex pd_ex;
  localaddr_arg localnet;
  dnat_arg dnat;

  /* NULL input strings should fail gracefully */
  assert(parse_proxy_url(NULL, &pd_ex) == 0);
  assert(parse_localnet_entry(NULL, &localnet) == 0);
  assert(parse_dnat_entry(NULL, &dnat) == 0);

  TEST_PASS();
}

/* Test empty strings */
void test_empty_strings() {
  TEST_START("empty_strings");
  proxy_data_ex pd_ex;
  localaddr_arg localnet;
  dnat_arg dnat;

  assert(parse_proxy_url("", &pd_ex) == 0);
  assert(parse_localnet_entry("", &localnet) == 0);
  assert(parse_dnat_entry("", &dnat) == 0);

  TEST_PASS();
}

/* Test whitespace handling */
void test_whitespace_handling() {
  TEST_START("whitespace_handling");
  proxy_data_ex pd_ex;

  /* Test that parser handles whitespace without crashing */
  /* Actual result may vary based on implementation */
  parse_proxy_url("socks5:// 127.0.0.1:1080", &pd_ex);
  parse_proxy_url("socks5://127.0.0.1 :1080", &pd_ex);
  parse_proxy_url("socks5:// localhost:1080", &pd_ex);
  parse_proxy_url("socks5://localhost :1080", &pd_ex);

  TEST_PASS();
}

/* Test very long strings (buffer overflow protection) */
void test_long_strings() {
  TEST_START("long_strings");
  char long_url[MAX_TEST_STRING + 100];
  proxy_data_ex pd_ex;

  /* Create a very long hostname */
  strcpy(long_url, "socks5://");
  memset(long_url + 9, 'a', MAX_TEST_STRING);
  long_url[MAX_TEST_STRING + 9] = '\0';
  strcat(long_url, ":1080");

  /* Should handle gracefully (might fail parsing but no crash) */
  int result = parse_proxy_url(long_url, &pd_ex);
  (void)result; /* Result doesn't matter, just shouldn't crash */

  TEST_PASS();
}

/* Test special characters */
void test_special_characters() {
  TEST_START("special_characters");
  proxy_data_ex pd_ex;

  /* Special chars in password (without @ which is delimiter) */
  assert(parse_proxy_url("socks5://user:p!ss:w0rd@127.0.0.1:1080", &pd_ex) == 1);
  assert(strcmp(pd_ex.pd.user, "user") == 0);
  assert(strcmp(pd_ex.pd.pass, "p!ss:w0rd") == 0);
  
    /* Convert expected IP string to binary and compare to the union representation.
     This avoids passing a union directly to strcmp (which expects a string). */
    struct in_addr expected_v4;
    int rc = inet_pton(AF_INET, "127.0.0.1", &expected_v4);
    assert(rc == 1);
    /* inet_pton stored IPv4 in network byte order into pd_ex.pd.ip.addr.v6 buffer
      (first 4 bytes) so compare those bytes to expected_v4. */
    assert(memcmp(pd_ex.pd.ip.addr.v6, &expected_v4, sizeof(expected_v4)) == 0);
    /* port is stored in network byte order, convert to host order for comparison */
    assert(ntohs(pd_ex.pd.port) == 1080);

  TEST_PASS();
}

/* Test boundary values */
void test_boundary_values() {
  TEST_START("boundary_values");
  localaddr_arg localnet;

  assert(parse_localnet_entry("0.0.0.0/0", &localnet) == 1);
  assert(parse_localnet_entry("192.168.1.1/32", &localnet) == 1);
  assert(parse_localnet_entry("::1/128", &localnet) == 1);

  dnat_arg dnat;
  assert(parse_dnat_entry("1.1.1.1:1-2.2.2.2:1", &dnat) == 1);
  assert(dnat.orig_port == 1);
  assert(parse_dnat_entry("1.1.1.1:65535-2.2.2.2:65535", &dnat) == 1);
  assert(dnat.orig_port == 65535);

  TEST_PASS();
}

/* Test malformed inputs */
void test_malformed_inputs() {
  TEST_START("malformed_inputs");
  proxy_data_ex pd_ex;

  /* Parser may be lenient, just check it doesn't crash */
  parse_proxy_url("socks5:///127.0.0.1:1080", &pd_ex);
  parse_proxy_url("socks5://127.0.0.1::1080", &pd_ex);

  TEST_PASS();
}

int main() {
  printf("=== Edge Cases & Error Handling Tests ===\n");

  test_null_pointers();
  test_empty_strings();
  test_whitespace_handling();
  test_long_strings();
  test_special_characters();
  test_boundary_values();
  test_malformed_inputs();

  printf("\n✓ All edge case tests passed!\n");
  return 0;
}
