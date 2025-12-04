/***************************************************************************
                          config_print.h  -  description
                             -------------------
    Configuration printing module for proxychains-ng
    Handles printing effective configuration for --show-config
 ***************************************************************************/
#ifndef CONFIG_PRINT_H
#define CONFIG_PRINT_H

#include "core.h"
#include "argparse.h"
#include "common.h"

/*
 * Print the effective configuration (merged file + CLI).
 * This outputs a human-readable summary of the active configuration
 * including chain mode, proxies, localnets, DNAT rules, etc.
 *
 * Parameters:
 *   cli_opts - CLI options (for potential future use)
 *   pd       - Proxy data array
 *   count    - Number of proxies
 *   ct       - Chain type
 */
void print_effective_config(const cli_options *cli_opts, proxy_data *pd, 
                            unsigned int count, chain_type ct);

#endif /* CONFIG_PRINT_H */
