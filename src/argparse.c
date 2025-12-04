#include "argparse.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Serialize CLI options to environment variables */
void serialize_cli_options_to_env(const cli_options *opts) {
  char buf[32];

  /* Ignore config file flag */
  if (opts->ignore_config_file) {
    setenv(PROXYCHAINS_CLI_IGNORE_CONFIG, "1", 1);
  }

  /* Chain mode */
  if (opts->has_chain_mode) {
    const char *mode_str = NULL;
    switch (opts->chain_mode) {
    case STRICT_TYPE:
      mode_str = "strict";
      break;
    case DYNAMIC_TYPE:
      mode_str = "dynamic";
      break;
    case RANDOM_TYPE:
      mode_str = "random";
      break;
    case ROUND_ROBIN_TYPE:
      mode_str = "round_robin";
      break;
    }
    if (mode_str)
      setenv(PROXYCHAINS_CLI_CHAIN_MODE, mode_str, 1);
  }

  /* Chain length */
  if (opts->has_chain_len) {
    snprintf(buf, sizeof(buf), "%u", opts->chain_len);
    setenv(PROXYCHAINS_CLI_CHAIN_LEN, buf, 1);
  }

  /* DNS mode - consolidated */
  if (opts->has_dns_mode) {
    setenv(PROXYCHAINS_CLI_DNS, opts->dns_value, 1);
  }

  /* Quiet mode */
  if (opts->has_quiet) {
    setenv(PROXYCHAINS_CLI_QUIET, opts->quiet_mode ? "1" : "0", 1);
  }

  /* Debug level */
  if (opts->has_debug_level) {
    snprintf(buf, sizeof(buf), "%d", opts->debug_level);
    setenv(PROXYCHAINS_CLI_DEBUG_LEVEL, buf, 1);
  }

  /* Timeouts */
  if (opts->has_tcp_read_timeout) {
    snprintf(buf, sizeof(buf), "%d", opts->tcp_read_timeout);
    setenv(PROXYCHAINS_CLI_TCP_READ_TIMEOUT, buf, 1);
  }
  if (opts->has_tcp_connect_timeout) {
    snprintf(buf, sizeof(buf), "%d", opts->tcp_connect_timeout);
    setenv(PROXYCHAINS_CLI_TCP_CONNECT_TIMEOUT, buf, 1);
  }

  /* Remote DNS subnet */
  if (opts->has_remote_dns_subnet) {
    snprintf(buf, sizeof(buf), "%u", opts->remote_dns_subnet);
    setenv(PROXYCHAINS_CLI_REMOTE_DNS_SUBNET, buf, 1);
  }

  /* List directives */
  if (opts->has_localnet) {
    setenv(PROXYCHAINS_CLI_LOCALNET, opts->localnet_list, 1);
  }
  if (opts->has_dnat) {
    setenv(PROXYCHAINS_CLI_DNAT, opts->dnat_list, 1);
  }
  if (opts->has_proxy) {
    setenv(PROXYCHAINS_CLI_PROXY, opts->proxy_list, 1);
  }

  /* Show config */
  if (opts->has_show_config) {
    setenv(PROXYCHAINS_CLI_SHOW_CONFIG, opts->show_config ? "1" : "0", 1);
  }
}

/* Deserialize CLI options from environment variables */
void deserialize_cli_options_from_env(cli_options *opts) {
  char *env;

  memset(opts, 0, sizeof(*opts));

  /* Ignore config file */
  env = getenv(PROXYCHAINS_CLI_IGNORE_CONFIG);
  if (env && *env == '1') {
    opts->ignore_config_file = 1;
  }

  /* Chain mode */
  env = getenv(PROXYCHAINS_CLI_CHAIN_MODE);
  if (env) {
    opts->has_chain_mode = 1;
    if (!strcmp(env, "strict"))
      opts->chain_mode = STRICT_TYPE;
    else if (!strcmp(env, "dynamic"))
      opts->chain_mode = DYNAMIC_TYPE;
    else if (!strcmp(env, "random"))
      opts->chain_mode = RANDOM_TYPE;
    else if (!strcmp(env, "round_robin"))
      opts->chain_mode = ROUND_ROBIN_TYPE;
  }

  /* Chain length */
  env = getenv(PROXYCHAINS_CLI_CHAIN_LEN);
  if (env) {
    opts->has_chain_len = 1;
    opts->chain_len = atoi(env);
  }

  /* DNS mode */
  env = getenv(PROXYCHAINS_CLI_DNS);
  if (env) {
    opts->has_dns_mode = 1;
    strncpy(opts->dns_value, env, sizeof(opts->dns_value) - 1);
  }

  /* Quiet mode */
  env = getenv(PROXYCHAINS_CLI_QUIET);
  if (env) {
    opts->has_quiet = 1;
    opts->quiet_mode = (*env == '1');
  }

  /* Debug level */
  env = getenv(PROXYCHAINS_CLI_DEBUG_LEVEL);
  if (env) {
    opts->has_debug_level = 1;
    opts->debug_level = atoi(env);
  }

  /* Timeouts */
  env = getenv(PROXYCHAINS_CLI_TCP_READ_TIMEOUT);
  if (env) {
    opts->has_tcp_read_timeout = 1;
    opts->tcp_read_timeout = atoi(env);
  }
  env = getenv(PROXYCHAINS_CLI_TCP_CONNECT_TIMEOUT);
  if (env) {
    opts->has_tcp_connect_timeout = 1;
    opts->tcp_connect_timeout = atoi(env);
  }

  /* Remote DNS subnet */
  env = getenv(PROXYCHAINS_CLI_REMOTE_DNS_SUBNET);
  if (env) {
    opts->has_remote_dns_subnet = 1;
    opts->remote_dns_subnet = atoi(env);
  }

  /* List directives */
  env = getenv(PROXYCHAINS_CLI_LOCALNET);
  if (env) {
    opts->has_localnet = 1;
    strncpy(opts->localnet_list, env, sizeof(opts->localnet_list) - 1);
  }
  env = getenv(PROXYCHAINS_CLI_DNAT);
  if (env) {
    opts->has_dnat = 1;
    strncpy(opts->dnat_list, env, sizeof(opts->dnat_list) - 1);
  }
  env = getenv(PROXYCHAINS_CLI_PROXY);
  if (env) {
    opts->has_proxy = 1;
    strncpy(opts->proxy_list, env, sizeof(opts->proxy_list) - 1);
  }
  env = getenv(PROXYCHAINS_CLI_SHOW_CONFIG);
  if (env) {
    opts->has_show_config = 1;
    opts->show_config = (*env == '1');
  }
}

/* Parse chain mode with optional inline length */
int parse_chain_mode(const char *arg, chain_type *mode, int *chain_len) {
  char mode_str[32];
  const char *colon = strchr(arg, ':');

  *chain_len = -1; /* -1 means not specified */

  /* Extract mode string (before colon if present) */
  if (colon) {
    size_t len = colon - arg;
    if (len >= sizeof(mode_str))
      return -1;
    memcpy(mode_str, arg, len);
    mode_str[len] = '\0';
  } else {
    strncpy(mode_str, arg, sizeof(mode_str) - 1);
    mode_str[sizeof(mode_str) - 1] = '\0';
  }

  /* Parse mode */
  if (!*mode_str || !strcmp(mode_str, "s") || !strcmp(mode_str, "strict")) {
    *mode = STRICT_TYPE;
  } else if (!strcmp(mode_str, "d") || !strcmp(mode_str, "dynamic")) {
    *mode = DYNAMIC_TYPE;
  } else if (!strcmp(mode_str, "rr") || !strcmp(mode_str, "round_robin")) {
    *mode = ROUND_ROBIN_TYPE;
  } else if (!strcmp(mode_str, "rd") || !strcmp(mode_str, "random")) {
    *mode = RANDOM_TYPE;
  } else {
    fprintf(stderr, "error: invalid chain mode: %s\n", mode_str);
    fprintf(stderr,
            "valid modes: s/strict, d/dynamic, rr/round_robin, rd/random\n");
    return -1;
  }

  /* Parse chain length after colon (only for random and round_robin) */
  if (colon) {
    if (*mode != RANDOM_TYPE && *mode != ROUND_ROBIN_TYPE) {
      fprintf(stderr, "error: chain length not supported for %s mode\n",
              mode_str);
      fprintf(stderr,
              "chain length only supported for random and round_robin modes\n");
      return -1;
    }

    *chain_len = atoi(colon + 1);
    if (*chain_len <= 0) {
      fprintf(stderr, "error: chain_len must be positive, got: %s\n",
              colon + 1);
      return -1;
    }
  }

  return 0;
}

/* Parse DNS value */
int parse_dns_value(const char *arg, char *dns_value, size_t max_len) {
  if (!arg || !*arg) {
    /* Empty argument defaults to "proxy" */
    strncpy(dns_value, "proxy", max_len - 1);
    dns_value[max_len - 1] = '\0';
    return 0;
  }

  /* Check for known keywords */
  if (!strcmp(arg, "p") || !strcmp(arg, "proxy") || !strcmp(arg, "o") ||
      !strcmp(arg, "old") || !strcmp(arg, "off") || !strcmp(arg, "none")) {

    /* Normalize */
    if (!strcmp(arg, "p"))
      strcpy(dns_value, "proxy");
    else if (!strcmp(arg, "o"))
      strcpy(dns_value, "old");
    else if (!strcmp(arg, "none"))
      strcpy(dns_value, "off");
    else
      strncpy(dns_value, arg, max_len - 1);
    dns_value[max_len - 1] = '\0';
    return 0;
  }

  /* Otherwise assume it's IP:PORT format - basic validation */
  if (!strchr(arg, ':')) {
    fprintf(stderr, "error: invalid DNS value: %s\n", arg);
    fprintf(stderr, "expected: proxy, old, off, or IP:PORT / [IPv6]:PORT\n");
    return -1;
  }

  strncpy(dns_value, arg, max_len - 1);
  dns_value[max_len - 1] = '\0';
  return 0;
}

// Validate CLI options */
int validate_cli_options(const cli_options *opts) {
  /* Check for mutually exclusive options */
  if (opts->ignore_config_file && opts->config_file_path) {
    fprintf(stderr,
            "Error: --ignore-config-file and --config-file are mutually "
            "exclusive\n");
    return -1;
  }

  /* Check chain_len is valid */
  if (opts->has_chain_len && opts->chain_len == 0) {
    fprintf(stderr, "Error: chain_len must be greater than 0\n");
    return -1;
  }

  /* Check remote_dns_subnet is valid (0-255) */
  if (opts->has_remote_dns_subnet && opts->remote_dns_subnet > 255) {
    fprintf(stderr, "Error: remote_dns_subnet must be between 0 and 255\n");
    return -1;
  }

  /* Check timeouts are positive */
  if (opts->has_tcp_read_timeout && opts->tcp_read_timeout < 0) {
    fprintf(stderr, "Error: tcp_read_timeout must be positive\n");
    return -1;
  }
  if (opts->has_tcp_connect_timeout && opts->tcp_connect_timeout < 0) {
    fprintf(stderr, "Error: tcp_connect_timeout must be positive\n");
    return -1;
  }

  return 0; /* Valid */
}

/* Helper to append to list with comma separator */
void append_to_list(char *list, size_t max_size, const char *item) {
  if (strlen(list) > 0) {
    strncat(list, ",", max_size - strlen(list) - 1);
  }
  strncat(list, item, max_size - strlen(list) - 1);
}

/**
 * Parse command line arguments and return CLI options
 * Returns: 0 on success, 1 on error (usage shown), 2 on help, 3 on version
 */
int parse_arguments(int argc, char *argv[], cli_options *opts,
                    int *start_argv) {
  int tmp_chain_len;

  *start_argv = 1;
  memset(opts, 0, sizeof(*opts));

  /* Parse command line arguments */
  while (*start_argv < argc && argv[*start_argv][0] == '-') {
    const char *arg = argv[*start_argv];

    /* Help */
    if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
      return 2; /* Help requested */
    }

    /* Version */
    else if (!strcmp(arg, "-v") || !strcmp(arg, "--version")) {
      return 3; /* Version requested */
    }

    /* Quiet mode */
    else if (!strcmp(arg, "-q") || !strcmp(arg, "--quiet")) {
      opts->has_quiet = 1;
      opts->quiet_mode = 1;
      (*start_argv)++;
    } else if (!strcmp(arg, "--no-quiet")) {
      opts->has_quiet = 1;
      opts->quiet_mode = 0;
      (*start_argv)++;
    }

    /* Config file */
    else if (!strcmp(arg, "-f") || !strcmp(arg, "--config-file")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->config_file_path = argv[*start_argv + 1];
      *start_argv += 2;
    } else if (!strcmp(arg, "--ignore-config-file")) {
      opts->ignore_config_file = 1;
      (*start_argv)++;
    }

    /* Show config */
    else if (!strcmp(arg, "--show-config")) {
      opts->has_show_config = 1;
      opts->show_config = 1;
      (*start_argv)++;
    }

    /* Chain mode */
    else if (!strcmp(arg, "-c") || !strcmp(arg, "--chain")) {
      if (*start_argv + 1 >= argc)
        return 1;
      if (parse_chain_mode(argv[*start_argv + 1], &opts->chain_mode,
                           &tmp_chain_len) != 0) {
        return 1;
      }
      opts->has_chain_mode = 1;
      if (tmp_chain_len > 0) {
        opts->has_chain_len = 1;
        opts->chain_len = tmp_chain_len;
      }
      *start_argv += 2;
    } else if (!strcmp(arg, "-l") || !strcmp(arg, "--chain-len")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_chain_len = 1;
      opts->chain_len = atoi(argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* DNS mode */
    else if (!strcmp(arg, "-d") || !strcmp(arg, "--dns")) {
      if (*start_argv + 1 >= argc)
        return 1;
      if (parse_dns_value(argv[*start_argv + 1], opts->dns_value,
                          sizeof(opts->dns_value)) != 0) {
        return 1;
      }
      opts->has_dns_mode = 1;
      *start_argv += 2;
    }

    /* Debug level */
    else if (!strcmp(arg, "-D") || !strcmp(arg, "--debug-level")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_debug_level = 1;
      opts->debug_level = atoi(argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* Timeouts */
    else if (!strcmp(arg, "-R") || !strcmp(arg, "--tcp-read-timeout")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_tcp_read_timeout = 1;
      opts->tcp_read_timeout = atoi(argv[*start_argv + 1]);
      *start_argv += 2;
    } else if (!strcmp(arg, "-T") || !strcmp(arg, "--tcp-connect-timeout")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_tcp_connect_timeout = 1;
      opts->tcp_connect_timeout = atoi(argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* Remote DNS subnet */
    else if (!strcmp(arg, "-S") || !strcmp(arg, "--remote-dns-subnet")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_remote_dns_subnet = 1;
      opts->remote_dns_subnet = atoi(argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* Localnet (repeatable) */
    else if (!strcmp(arg, "-n") || !strcmp(arg, "--localnet")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_localnet = 1;
      append_to_list(opts->localnet_list, sizeof(opts->localnet_list),
                     argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* DNAT (repeatable) */
    else if (!strcmp(arg, "--dnat")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_dnat = 1;
      append_to_list(opts->dnat_list, sizeof(opts->dnat_list),
                     argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* Proxy (repeatable) */
    else if (!strcmp(arg, "-P") || !strcmp(arg, "--proxy")) {
      if (*start_argv + 1 >= argc)
        return 1;
      opts->has_proxy = 1;
      append_to_list(opts->proxy_list, sizeof(opts->proxy_list),
                     argv[*start_argv + 1]);
      *start_argv += 2;
    }

    /* Unknown option */
    else {
      fprintf(stderr, "Unknown option: %s\n", arg);
      return 1;
    }
  }

  /* Check if program name is provided; allow missing program if --show-config
   */
  if (*start_argv >= argc) {
    if (opts->has_show_config && opts->show_config) {
      /* show-config only mode; we accept no program */
      return 0;
    }
    return 1;
  }

  /* Validate CLI options */
  if (validate_cli_options(opts) != 0) {
    return 1;
  }

  return 0; /* Success */
}
