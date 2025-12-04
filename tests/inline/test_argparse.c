/***************************************************************************
 * test_argparse.c - Test CLI argument parsing
 ***************************************************************************/

#include "../../src/argparse.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_START(name) printf("Running: %s...", name);
#define TEST_PASS() printf(" PASS\n");

/* Test quiet flag */
void test_parse_quiet() {
  TEST_START("parse_quiet");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-q", "curl", "example.com"};
  int argc = 4;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_quiet == 1);
  assert(opts.quiet_mode == 1);
  assert(start_argv == 2);
  TEST_PASS();
}

/* Test config file option */
void test_parse_config_file() {
  TEST_START("parse_config_file");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-f", "/etc/proxychains.conf", "curl",
                  "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.config_file_path != NULL);
  assert(strcmp(opts.config_file_path, "/etc/proxychains.conf") == 0);
  TEST_PASS();
}

/* Test chain mode simple */
void test_parse_chain_mode() {
  TEST_START("parse_chain_mode");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-c", "strict", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_chain_mode == 1);
  assert(opts.chain_mode == STRICT_TYPE);
  TEST_PASS();
}

/* Test chain mode with inline length (random/round_robin only) */
void test_parse_chain_mode_inline_length() {
  TEST_START("parse_chain_mode_inline_length");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-c", "random:5", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_chain_mode == 1);
  assert(opts.chain_mode == RANDOM_TYPE);
  assert(opts.has_chain_len == 1);
  assert(opts.chain_len == 5);
  TEST_PASS();
}

/* Test only random and round_robin support inline length */
void test_all_chain_modes_inline() {
  TEST_START("all_chain_modes_inline");
  cli_options opts;
  int start_argv;
  char *argv[5];
  argv[0] = "proxychains4";
  argv[2] = ""; // set later
  argv[1] = "-c";
  argv[3] = "curl";
  argv[4] = "example.com";

  /* random:2 - SHOULD WORK */
  argv[2] = "random:2";
  assert(parse_arguments(5, argv, &opts, &start_argv) == 0);
  assert(opts.chain_mode == RANDOM_TYPE && opts.chain_len == 2);

  /* round_robin:10 - SHOULD WORK */
  argv[2] = "round_robin:10";
  assert(parse_arguments(5, argv, &opts, &start_argv) == 0);
  assert(opts.chain_mode == ROUND_ROBIN_TYPE && opts.chain_len == 10);

  /* strict:3 - SHOULD FAIL */
  argv[2] = "strict:3";
  assert(parse_arguments(5, argv, &opts, &start_argv) == 1);

  /* dynamic:4 - SHOULD FAIL */
  argv[2] = "dynamic:4";
  assert(parse_arguments(5, argv, &opts, &start_argv) == 1);

  TEST_PASS();
}

/* Test DNS mode */
void test_parse_dns_mode() {
  TEST_START("parse_dns_mode");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-d", "proxy", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_dns_mode == 1);
  assert(strcmp(opts.dns_value, "proxy") == 0);
  TEST_PASS();
}

/* Test proxy list */
void test_parse_proxy_list() {
  TEST_START("parse_proxy_list");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-P", "socks5://127.0.0.1:1080", "curl",
                  "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_proxy == 1);
  /* Exact string expected for single proxy entry */
  assert(strcmp(opts.proxy_list, "socks5://127.0.0.1:1080") == 0);
  TEST_PASS();
}

/* Test multiple proxy entries */
void test_parse_multiple_proxies() {
  TEST_START("parse_multiple_proxies");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4",         "-P",   "socks5://proxy1:1080", "-P",
                  "socks5://proxy2:1080", "curl", "example.com"};
  int argc = 7;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_proxy == 1);
  /* Exact string expected for two proxies (comma separated, no spaces) */
  assert(strcmp(opts.proxy_list,
                "socks5://proxy1:1080,socks5://proxy2:1080") == 0);
  TEST_PASS();
}

/* Test localnet */
void test_parse_localnet() {
  TEST_START("parse_localnet");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-n", "192.168.0.0/16", "curl",
                  "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_localnet == 1);
  assert(strcmp(opts.localnet_list, "192.168.0.0/16") == 0);
  TEST_PASS();
}

/* Test DNAT */
void test_parse_dnat() {
  TEST_START("parse_dnat");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "--dnat", "1.1.1.1-2.2.2.2", "curl",
                  "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_dnat == 1);
  assert(strcmp(opts.dnat_list, "1.1.1.1-2.2.2.2") == 0);
  TEST_PASS();
}

/* Test timeouts */
void test_parse_timeouts() {
  TEST_START("parse_timeouts");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-R",   "5000",       "-T",
                  "10000",        "curl", "example.com"};
  int argc = 7;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_tcp_read_timeout == 1);
  assert(opts.tcp_read_timeout == 5000);
  assert(opts.has_tcp_connect_timeout == 1);
  assert(opts.tcp_connect_timeout == 10000);
  TEST_PASS();
}

/* Test remote DNS subnet */
void test_parse_remote_dns_subnet() {
  TEST_START("parse_remote_dns_subnet");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-S", "224", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_remote_dns_subnet == 1);
  assert(opts.remote_dns_subnet == 224);
  TEST_PASS();
}

/* Test combined options */
void test_parse_combined_options() {
  TEST_START("parse_combined_options");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-q",         "-c", "random:3",
                  "-d",           "proxy",      "-P", "socks5://127.0.0.1:1080",
                  "curl",         "example.com"};
  int argc = 10;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 0);
  assert(opts.has_quiet == 1);

  assert(opts.has_chain_mode == 1);
  assert(opts.chain_mode == RANDOM_TYPE);

  assert(opts.has_chain_len == 1);
  assert(opts.chain_len == 3);

  assert(opts.has_dns_mode == 1);
  assert(strcmp(opts.dns_value, "proxy") == 0);

  assert(opts.has_proxy == 1);
  assert(strcmp(opts.proxy_list, "socks5://127.0.0.1:1080") == 0);
  TEST_PASS();
}

/* Test help flag */
void test_parse_help() {
  TEST_START("parse_help");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-h"};
  int argc = 2;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 2); /* Help requested */
  TEST_PASS();
}

/* Test version flag */
void test_parse_version() {
  TEST_START("parse_version");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-v"};
  int argc = 2;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 3); /* Version requested */
  TEST_PASS();
}

/* Test missing argument */
void test_parse_missing_argument() {
  TEST_START("parse_missing_argument");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-c"}; /* Missing chain mode value */
  int argc = 2;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1); /* Error */
  TEST_PASS();
}

/* Additional error cases */
void test_parse_missing_argument_config_file() {
  TEST_START("parse_missing_argument_config_file");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-f"}; /* Missing config path */
  int argc = 2;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_missing_argument_dns() {
  TEST_START("parse_missing_argument_dns");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-d"}; /* Missing dns value */
  int argc = 2;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_invalid_chain_mode() {
  TEST_START("parse_invalid_chain_mode");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-c", "unknown", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_chain_len_zero() {
  TEST_START("parse_chain_len_zero");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-l", "0", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_invalid_dns_value() {
  TEST_START("parse_invalid_dns_value");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-d", "invalid", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_remote_dns_subnet_out_of_range() {
  TEST_START("parse_remote_dns_subnet_out_of_range");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-S", "256", "curl", "example.com"};
  int argc = 5;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_negative_timeouts() {
  TEST_START("parse_negative_timeouts");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-R", "-1", "-T", "-5", "curl", "example.com"};
  int argc = 7;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_conflicting_options() {
  TEST_START("parse_conflicting_options");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-f", "/etc/proxychains.conf", "--ignore-config-file", "curl", "example.com"};
  int argc = 6;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

void test_parse_unknown_option() {
  TEST_START("parse_unknown_option");
  cli_options opts;
  int start_argv;
  char *argv[] = {"proxychains4", "-x", "curl", "example.com"};
  int argc = 4;

  int result = parse_arguments(argc, argv, &opts, &start_argv);

  assert(result == 1);
  TEST_PASS();
}

/* Test serialize/deserialize to/from environment variables */
void clear_cli_env_vars(void) {
  unsetenv(PROXYCHAINS_CLI_IGNORE_CONFIG);
  unsetenv(PROXYCHAINS_CLI_CHAIN_MODE);
  unsetenv(PROXYCHAINS_CLI_CHAIN_LEN);
  unsetenv(PROXYCHAINS_CLI_DNS);
  unsetenv(PROXYCHAINS_CLI_QUIET);
  unsetenv(PROXYCHAINS_CLI_DEBUG_LEVEL);
  unsetenv(PROXYCHAINS_CLI_TCP_READ_TIMEOUT);
  unsetenv(PROXYCHAINS_CLI_TCP_CONNECT_TIMEOUT);
  unsetenv(PROXYCHAINS_CLI_REMOTE_DNS_SUBNET);
  unsetenv(PROXYCHAINS_CLI_LOCALNET);
  unsetenv(PROXYCHAINS_CLI_DNAT);
  unsetenv(PROXYCHAINS_CLI_PROXY);
  unsetenv(PROXYCHAINS_CLI_SHOW_CONFIG);
}

void test_serialize_deserialize_cli_options() {
  TEST_START("serialize_deserialize_cli_options");
  cli_options opts;
  cli_options opts2;
  int start_argv;

  /* prepare opts */
  memset(&opts, 0, sizeof(opts));
  opts.ignore_config_file = 1;
  opts.has_chain_mode = 1;
  opts.chain_mode = RANDOM_TYPE;
  opts.has_chain_len = 1;
  opts.chain_len = 5;
  opts.has_dns_mode = 1;
  strncpy(opts.dns_value, "127.0.0.1:1053", sizeof(opts.dns_value) - 1);
  opts.has_quiet = 1;
  opts.quiet_mode = 1;
  opts.has_debug_level = 1;
  opts.debug_level = 2;
  opts.has_tcp_read_timeout = 1;
  opts.tcp_read_timeout = 1000;
  opts.has_tcp_connect_timeout = 1;
  opts.tcp_connect_timeout = 2000;
  opts.has_remote_dns_subnet = 1;
  opts.remote_dns_subnet = 224;
  opts.has_localnet = 1;
  strncpy(opts.localnet_list, "192.168.0.0/16", sizeof(opts.localnet_list) - 1);
  opts.has_dnat = 1;
  strncpy(opts.dnat_list, "1.1.1.1-2.2.2.2", sizeof(opts.dnat_list)-1);
  opts.has_proxy = 1;
  strncpy(opts.proxy_list,
          "socks5://127.0.0.1:1080,socks5://proxy2:1080",
          sizeof(opts.proxy_list) - 1);
  opts.has_show_config = 1;
  opts.show_config = 1;

  /* Ensure environment clean */
  clear_cli_env_vars();

  serialize_cli_options_to_env(&opts);

  memset(&opts2, 0, sizeof(opts2));
  /* Ensure environment clean */
  assert(opts2.ignore_config_file == 0); // enough to show it's clean

  deserialize_cli_options_from_env(&opts2);

  /* Validate round-tripped values */
  assert(opts2.ignore_config_file == 1);
  assert(opts2.has_chain_mode == 1);
  assert(opts2.chain_mode == RANDOM_TYPE);
  assert(opts2.has_chain_len == 1);
  assert(opts2.chain_len == 5);
  assert(opts2.has_dns_mode == 1);
  assert(strcmp(opts2.dns_value, "127.0.0.1:1053") == 0);
  assert(opts2.has_quiet == 1);
  assert(opts2.quiet_mode == 1);
  assert(opts2.has_debug_level == 1);
  assert(opts2.debug_level == 2);
  assert(opts2.has_tcp_read_timeout == 1);
  assert(opts2.tcp_read_timeout == 1000);
  assert(opts2.has_tcp_connect_timeout == 1);
  assert(opts2.tcp_connect_timeout == 2000);
  assert(opts2.has_remote_dns_subnet == 1);
  assert(opts2.remote_dns_subnet == 224);
  assert(opts2.has_localnet == 1);
  assert(strcmp(opts2.localnet_list, "192.168.0.0/16") == 0);
  assert(opts2.has_dnat == 1);
  assert(strcmp(opts2.dnat_list, "1.1.1.1-2.2.2.2") == 0);
  assert(opts2.has_proxy == 1);
  assert(strcmp(opts2.proxy_list, "socks5://127.0.0.1:1080,socks5://proxy2:1080") == 0);
  assert(opts2.has_show_config == 1);
  assert(opts2.show_config == 1);

  /* cleanup env */
  clear_cli_env_vars();

  TEST_PASS();
}

int main() {
  printf("=== CLI Argument Parsing Tests ===\n");

  test_parse_quiet();
  test_parse_config_file();
  test_parse_chain_mode();
  test_parse_chain_mode_inline_length();
  test_all_chain_modes_inline();
  test_parse_dns_mode();
  test_parse_proxy_list();
  test_parse_multiple_proxies();
  test_parse_localnet();
  test_parse_dnat();
  test_parse_timeouts();
  test_parse_remote_dns_subnet();
  test_parse_combined_options();
  test_parse_help();
  test_parse_version();

  /* Error cases */
  test_parse_missing_argument();
  test_parse_missing_argument_config_file();
  test_parse_missing_argument_dns();
  test_parse_invalid_chain_mode();
  test_parse_chain_len_zero();
  test_parse_invalid_dns_value();
  test_parse_remote_dns_subnet_out_of_range();
  test_parse_negative_timeouts();
  test_parse_conflicting_options();
  test_parse_unknown_option();
  test_serialize_deserialize_cli_options();

  printf("\n✓ All argparse tests passed!\n");
  return 0;
}
