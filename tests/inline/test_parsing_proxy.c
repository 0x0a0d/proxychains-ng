/***************************************************************************
 * test_parsing_proxy.c - Test proxy URL parsing
 ***************************************************************************/

#include "../../src/parsing.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");

/* Test basic socks5 URL */
void test_parse_socks5_basic() {
  TEST_START("parse_socks5_basic");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks5://127.0.0.1:1080", &pd_ex);

  assert(result == 1);
  assert(pd_ex.pd.pt == SOCKS5_TYPE);
  TEST_PASS();
}

/* Test socks5h (remote DNS) */
void test_parse_socks5h() {
  TEST_START("parse_socks5h");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks5h://127.0.0.1:1080", &pd_ex);

  assert(result == 1);
  assert(pd_ex.pd.pt == SOCKS5_TYPE);
  assert(pd_ex.flags & PROXY_FLAG_REMOTE_DNS);
  TEST_PASS();
}

/* Test proxy with auth */
void test_parse_with_auth() {
  TEST_START("parse_with_auth");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks5://user:pass@127.0.0.1:1080", &pd_ex);

  assert(result == 1);
  assert(strcmp(pd_ex.pd.user, "user") == 0);
  assert(strcmp(pd_ex.pd.pass, "pass") == 0);
  TEST_PASS();
}

/* Test invalid URL */
void test_parse_invalid() {
  TEST_START("parse_invalid");
  proxy_data_ex pd_ex;

  assert(parse_proxy_url("invalid://host:1080", &pd_ex) == 0);
  assert(parse_proxy_url("socks5://host", &pd_ex) == 0); // missing port
  TEST_PASS();
}

/* Test IPv6 bracketed addresses */
void test_parse_socks5_ipv6() {
  TEST_START("parse_socks5_ipv6");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks5://[::1]:1080", &pd_ex);
  assert(result == 1);
  assert(pd_ex.pd.pt == SOCKS5_TYPE);
  assert(pd_ex.pd.ip.is_v6 == 1);
  struct in6_addr expected_v6;
  int rc = inet_pton(AF_INET6, "::1", &expected_v6);
  assert(rc == 1);
  assert(memcmp(pd_ex.pd.ip.addr.v6, &expected_v6, sizeof(expected_v6)) == 0);
  assert(ntohs(pd_ex.pd.port) == 1080);
  TEST_PASS();
}

/* Hostname parsing */
void test_parse_hostname() {
  TEST_START("parse_hostname");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks5://proxy.example.com:1080", &pd_ex);
  assert(result == 1);
  assert(pd_ex.pd.pt == SOCKS5_TYPE);
  assert(pd_ex.hostname[0] != '\0');
  assert(strcmp(pd_ex.hostname, "proxy.example.com") == 0);
  /* IP should be zeroed for hostname */
  char zero6[16] = {0};
  assert(memcmp(pd_ex.pd.ip.addr.v6, zero6, sizeof(zero6)) == 0);
  assert(ntohs(pd_ex.pd.port) == 1080);
  TEST_PASS();
}

/* HTTP scheme with auth */
void test_parse_http_with_auth() {
  TEST_START("parse_http_with_auth");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("http://user:pass@127.0.0.1:8080", &pd_ex);
  assert(result == 1);
  assert(pd_ex.pd.pt == HTTP_TYPE);
  assert(strcmp(pd_ex.pd.user, "user") == 0);
  assert(strcmp(pd_ex.pd.pass, "pass") == 0);
  assert(ntohs(pd_ex.pd.port) == 8080);
  TEST_PASS();
}

/* raw scheme */
void test_parse_raw() {
  TEST_START("parse_raw");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("raw://127.0.0.1:9000", &pd_ex);
  assert(result == 1);
  assert(pd_ex.pd.pt == RAW_TYPE);
  assert(ntohs(pd_ex.pd.port) == 9000);
  TEST_PASS();
}

/* socks4 auth should fail */
void test_socks4_auth_fails() {
  TEST_START("test_socks4_auth_fails");
  proxy_data_ex pd_ex;
  int result = parse_proxy_url("socks4://user:pass@127.0.0.1:1080", &pd_ex);
  assert(result == 0);
  TEST_PASS();
}

int main() {
  printf("=== Proxy URL Parsing Tests ===\n");

  test_parse_socks5_basic();
  test_parse_socks5h();
  test_parse_with_auth();
  test_parse_invalid();
  test_parse_socks5_ipv6();
  test_parse_hostname();
  test_parse_http_with_auth();
  test_parse_raw();
  test_socks4_auth_fails();

  printf("\n✓ All proxy parsing tests passed!\n");
  return 0;
}
