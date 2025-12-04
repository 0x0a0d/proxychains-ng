/***************************************************************************
                          cli_override.h  -  description
                             -------------------
    CLI override module for proxychains-ng
    Handles applying CLI options on top of config file settings
 ***************************************************************************/
#ifndef CLI_OVERRIDE_H
#define CLI_OVERRIDE_H

#include "core.h"
#include "argparse.h"
#include "common.h"

/*
 * Apply chain mode override from CLI options.
 * Sets the chain type (strict, dynamic, random, round_robin).
 */
void apply_chain_override(const cli_options *cli_opts, chain_type *ct);

/*
 * Apply chain length override from CLI options.
 * Sets proxychains_max_chain global.
 */
void apply_chain_len_override(const cli_options *cli_opts);

/*
 * Apply DNS mode override from CLI options.
 * Sets proxychains_resolver global and configures daemon if needed.
 */
void apply_dns_override(const cli_options *cli_opts);

/*
 * Apply quiet mode override from CLI options.
 * Sets proxychains_quiet_mode global.
 */
void apply_quiet_override(const cli_options *cli_opts);

/*
 * Apply timeout overrides from CLI options.
 * Sets tcp_read_time_out and tcp_connect_time_out globals.
 */
void apply_timeout_override(const cli_options *cli_opts);

/*
 * Apply remote DNS subnet override from CLI options.
 * Sets remote_dns_subnet global.
 */
void apply_dns_subnet_override(const cli_options *cli_opts);

/*
 * Apply localnet list override from CLI options.
 * Replaces existing localnet entries with CLI-specified ones.
 * Uses unified parser from parsing.c.
 */
void apply_localnet_override(const cli_options *cli_opts);

/*
 * Apply DNAT list override from CLI options.
 * Replaces existing DNAT entries with CLI-specified ones.
 * Uses unified parser from parsing.c.
 */
void apply_dnat_override(const cli_options *cli_opts);

/*
 * Apply proxy list override from CLI options.
 * Replaces existing proxy entries with CLI-specified ones.
 * Supports hostname resolution and socks5h auto-detection.
 *
 * Returns the number of proxies parsed, or 0 on error.
 */
int apply_proxy_override(const cli_options *cli_opts, proxy_data *pd, chain_type ct, int resolver_mode);

/*
 * Apply all CLI overrides in correct order.
 * This is the main entry point for applying CLI options.
 *
 * Parameters:
 *   cli_opts    - Deserialized CLI options from environment
 *   pd          - Proxy data array to populate (if has_proxy)
 *   proxy_count - Output: number of proxies (updated if has_proxy)
 *   ct          - Chain type pointer (updated if has_chain_mode)
 *
 * The function modifies global variables as appropriate:
 *   - proxychains_max_chain
 *   - proxychains_resolver
 *   - proxychains_quiet_mode
 *   - tcp_read_time_out
 *   - tcp_connect_time_out
 *   - remote_dns_subnet
 *   - localnet_addr[], num_localnet_addr
 *   - dnats[], num_dnats
 */
void apply_all_cli_overrides(const cli_options *cli_opts, proxy_data *pd, 
                             unsigned int *proxy_count, chain_type *ct);

#endif /* CLI_OVERRIDE_H */
