/***************************************************************************
                          cli_override.c  -  description
                             -------------------
    CLI override module for proxychains-ng
    Handles applying CLI options on top of config file settings
 ***************************************************************************/
/*     GPL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "cli_override.h"
#include "parsing.h"
#include "rdns.h"
#include "debug.h"

/* External globals from libproxychains.c */
extern int tcp_read_time_out;
extern int tcp_connect_time_out;
extern unsigned int proxychains_max_chain;
extern int proxychains_quiet_mode;
extern enum dns_lookup_flavor proxychains_resolver;
extern localaddr_arg localnet_addr[MAX_LOCALNET];
extern size_t num_localnet_addr;
extern dnat_arg dnats[MAX_DNAT];
extern size_t num_dnats;
extern unsigned int remote_dns_subnet;

/* Callback context for proxy parsing with hostname support */
typedef struct {
	proxy_data *pd;
	int count;
	int max_count;
	chain_type ct;
	int resolver_mode;
	int *has_socks5h;
} proxy_parse_ctx_t;

static const char* chain_type_to_str(chain_type ct) {
	switch(ct) {
		case STRICT_TYPE: return "strict";
		case DYNAMIC_TYPE: return "dynamic";
		case RANDOM_TYPE: return "random";
		case ROUND_ROBIN_TYPE: return "round_robin";
		default: return "unknown";
	}
}

/* Callback for parsing CLI proxy URLs using unified parser */
static int proxy_parse_callback(const char *token, void *ctx) {
	proxy_parse_ctx_t *pctx = (proxy_parse_ctx_t *)ctx;
	proxy_data_ex pd_ex;

	if(pctx->count >= pctx->max_count) return 0;

	if(!parse_proxy_url(token, &pd_ex)) {
		fprintf(stderr, "warning: invalid proxy URL: %s\n", token);
		return 0;
	}

	/* Track socks5h usage */
	if((pd_ex.flags & PROXY_FLAG_REMOTE_DNS) && pctx->has_socks5h) {
		*pctx->has_socks5h = 1;
	}

	/* Handle hostname resolution */
	if(pd_ex.hostname[0]) {
		/* Hostname needs resolution */
		if(pctx->ct == STRICT_TYPE && pctx->resolver_mode >= DNSLF_RDNS_START && pctx->count > 0) {
			/* Can use remote DNS for non-first proxy in strict mode */
			rdns_init(pctx->resolver_mode);
			ip_type4 internal_ip = rdns_get_ip_for_host(pd_ex.hostname, strlen(pd_ex.hostname));
			pd_ex.pd.ip.is_v6 = 0;
			pd_ex.pd.ip.addr.v4 = internal_ip;
			if(internal_ip.as_int == IPT4_INVALID.as_int) {
				fprintf(stderr, "warning: could not resolve hostname: %s\n", pd_ex.hostname);
				return 0;
			}
		} else {
			fprintf(stderr, "warning: proxy %s has hostname - ", pd_ex.hostname);
			fprintf(stderr, "non-numeric IPs are only allowed under the following circumstances:\n");
			fprintf(stderr, "chaintype == strict (%s), proxy is not first in list (%s), proxy_dns active (%s)\n",
				bool_str(pctx->ct == STRICT_TYPE), 
				bool_str(pctx->count > 0), 
				rdns_resolver_string(pctx->resolver_mode));
			return 0;
		}
	}

	/* Copy parsed data */
	pctx->pd[pctx->count] = pd_ex.pd;
	pctx->count++;
	return 1;
}

void apply_chain_override(const cli_options *cli_opts, chain_type *ct) {
	if(!cli_opts->has_chain_mode) return;
	
	*ct = cli_opts->chain_mode;
	PDEBUG_CLI(1, cli_opts, "CLI override: chain_type=%s\n", chain_type_to_str(cli_opts->chain_mode));
}

void apply_chain_len_override(const cli_options *cli_opts) {
	if(!cli_opts->has_chain_len) return;
	
	proxychains_max_chain = cli_opts->chain_len;
	PDEBUG_CLI(1, cli_opts, "CLI override: chain_len=%u\n", cli_opts->chain_len);
}

void apply_dns_override(const cli_options *cli_opts) {
	if(!cli_opts->has_dns_mode) return;

	if(!strcmp(cli_opts->dns_value, "proxy")) {
		proxychains_resolver = DNSLF_RDNS_THREAD;
	} else if(!strcmp(cli_opts->dns_value, "old")) {
		proxychains_resolver = DNSLF_FORKEXEC;
	} else if(!strcmp(cli_opts->dns_value, "off")) {
		proxychains_resolver = DNSLF_LIBC;
	} else {
		/* Parse IP:PORT or [IPv6]:PORT for daemon mode */
		char daemon_addr[64], daemon_port[8];
		struct sockaddr_in rdns_server_buffer;
		int parsed = 0;

		if(cli_opts->dns_value[0] == '[') {
			/* IPv6 format: [IPv6]:PORT - not fully implemented yet */
			fprintf(stderr, LOG_PREFIX "IPv6 daemon address not yet supported\n");
		} else if(sscanf(cli_opts->dns_value, "%63[^:]:%7s", daemon_addr, daemon_port) == 2) {
			rdns_server_buffer.sin_family = AF_INET;
			if(inet_pton(AF_INET, daemon_addr, &rdns_server_buffer.sin_addr) > 0) {
				rdns_server_buffer.sin_port = htons(atoi(daemon_port));
				proxychains_resolver = DNSLF_RDNS_DAEMON;
				rdns_set_daemon(&rdns_server_buffer);
				parsed = 1;
			}
		}
		if(!parsed) {
			fprintf(stderr, LOG_PREFIX "warning: invalid DNS daemon address: %s\n", cli_opts->dns_value);
		}
	}
	PDEBUG_CLI(1, cli_opts, "CLI override: dns=%s\n", cli_opts->dns_value);
}

void apply_quiet_override(const cli_options *cli_opts) {
	if(!cli_opts->has_quiet) return;
	
	proxychains_quiet_mode = cli_opts->quiet_mode;
	PDEBUG_CLI(1, cli_opts, "CLI override: quiet=%d\n", cli_opts->quiet_mode);
}

void apply_timeout_override(const cli_options *cli_opts) {
	if(cli_opts->has_tcp_read_timeout) {
		tcp_read_time_out = cli_opts->tcp_read_timeout;
		PDEBUG_CLI(1, cli_opts, "CLI override: tcp_read_timeout=%d\n", cli_opts->tcp_read_timeout);
	}
	if(cli_opts->has_tcp_connect_timeout) {
		tcp_connect_time_out = cli_opts->tcp_connect_timeout;
		PDEBUG_CLI(1, cli_opts, "CLI override: tcp_connect_timeout=%d\n", cli_opts->tcp_connect_timeout);
	}
}

void apply_dns_subnet_override(const cli_options *cli_opts) {
	if(!cli_opts->has_remote_dns_subnet) return;
	
	remote_dns_subnet = cli_opts->remote_dns_subnet;
	PDEBUG_CLI(1, cli_opts, "CLI override: remote_dns_subnet=%u\n", cli_opts->remote_dns_subnet);
}

void apply_localnet_override(const cli_options *cli_opts) {
	if(!cli_opts->has_localnet) return;

	/* Clear existing localnet entries */
	num_localnet_addr = 0;

	/* Parse each localnet spec from CLI using unified parser */
	char localnet_buffer[MAX_CLI_STRING];
	char *token, *saveptr;
	strncpy(localnet_buffer, cli_opts->localnet_list, sizeof(localnet_buffer) - 1);
	localnet_buffer[sizeof(localnet_buffer) - 1] = 0;

	/* Replace semicolons with commas */
	for(char *cp = localnet_buffer; *cp; cp++) {
		if(*cp == ';') *cp = ',';
	}

	token = strtok_r(localnet_buffer, ",", &saveptr);
	while(token && num_localnet_addr < MAX_LOCALNET) {
		/* Trim whitespace */
		while(*token && isspace((unsigned char)*token)) token++;
		char *end = token + strlen(token) - 1;
		while(end > token && isspace((unsigned char)*end)) *end-- = 0;

		if(*token) {
			if(parse_localnet_entry(token, &localnet_addr[num_localnet_addr])) {
				PDEBUG_CLI(2, cli_opts, "CLI localnet: %s\n", token);
				num_localnet_addr++;
			} else {
				fprintf(stderr, LOG_PREFIX "warning: invalid localnet spec: %s\n", token);
			}
		}
		token = strtok_r(NULL, ",", &saveptr);
	}

	PDEBUG_CLI(1, cli_opts, "CLI override: localnet (%zu entries)\n", num_localnet_addr);
}

void apply_dnat_override(const cli_options *cli_opts) {
	if(!cli_opts->has_dnat) return;

	/* Clear existing dnat entries */
	num_dnats = 0;

	/* Parse each dnat spec from CLI using unified parser */
	char dnat_buffer[MAX_CLI_STRING];
	char *token, *saveptr;
	strncpy(dnat_buffer, cli_opts->dnat_list, sizeof(dnat_buffer) - 1);
	dnat_buffer[sizeof(dnat_buffer) - 1] = 0;

	/* Replace semicolons with commas */
	for(char *cp = dnat_buffer; *cp; cp++) {
		if(*cp == ';') *cp = ',';
	}

	token = strtok_r(dnat_buffer, ",", &saveptr);
	while(token && num_dnats < MAX_DNAT) {
		/* Trim whitespace */
		while(*token && isspace((unsigned char)*token)) token++;
		char *end = token + strlen(token) - 1;
		while(end > token && isspace((unsigned char)*end)) *end-- = 0;

		if(*token) {
			if(parse_dnat_entry(token, &dnats[num_dnats])) {
				PDEBUG_CLI(2, cli_opts, "CLI dnat: %s\n", token);
				num_dnats++;
			} else {
				fprintf(stderr, LOG_PREFIX "warning: invalid dnat spec: %s\n", token);
			}
		}
		token = strtok_r(NULL, ",", &saveptr);
	}

	PDEBUG_CLI(1, cli_opts, "CLI override: dnat (%zu entries)\n", num_dnats);
}

int apply_proxy_override(const cli_options *cli_opts, proxy_data *pd, chain_type ct, int resolver_mode) {
	if(!cli_opts->has_proxy) return 0;

	/* Parse proxy URLs with hostname support */
	int has_socks5h = 0;
	proxy_parse_ctx_t pctx = { 
		.pd = pd, 
		.count = 0, 
		.max_count = MAX_CHAIN,
		.ct = ct,
		.resolver_mode = resolver_mode,
		.has_socks5h = &has_socks5h
	};
	split_and_process(cli_opts->proxy_list, proxy_parse_callback, &pctx);

	/* Auto-detect socks5h and enable proxy_dns if user didn't specify any DNS mode */
	if(has_socks5h && !cli_opts->has_dns_mode) {
		if(proxychains_resolver == DNSLF_LIBC) {
			proxychains_resolver = DNSLF_RDNS_THREAD;
			PDEBUG_CLI(1, cli_opts, "socks5h detected, auto-enabling proxy_dns\n");
		}
	}

	PDEBUG_CLI(1, cli_opts, "CLI override: proxy (%d entries)\n", pctx.count);
	return pctx.count;
}

void apply_all_cli_overrides(const cli_options *cli_opts, proxy_data *pd, 
                             unsigned int *proxy_count, chain_type *ct) {
	/* Apply overrides in logical order */
	apply_chain_override(cli_opts, ct);
	apply_chain_len_override(cli_opts);
	apply_dns_override(cli_opts);
	apply_quiet_override(cli_opts);
	apply_timeout_override(cli_opts);
	apply_dns_subnet_override(cli_opts);
	apply_localnet_override(cli_opts);
	apply_dnat_override(cli_opts);

	/* Proxy override needs chain type and resolver mode to be set first */
	if(cli_opts->has_proxy) {
		int count = apply_proxy_override(cli_opts, pd, *ct, proxychains_resolver);
		if(count > 0) {
			*proxy_count = count;
		}
	}
}
