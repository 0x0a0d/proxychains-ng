/***************************************************************************
                          config_print.c  -  description
                             -------------------
    Configuration printing module for proxychains-ng
    Handles printing effective configuration for --show-config
 ***************************************************************************/
/*     GPL */

#include <stdio.h>
#include <arpa/inet.h>

#include "config_print.h"
#include "rdns.h"

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

void print_effective_config(const cli_options *cli_opts, proxy_data *pd, 
                            unsigned int count, chain_type ct) {
	unsigned i;
	const char *mode_str = "unknown";
	(void)cli_opts; /* Currently unused, reserved for future use */

	switch(ct) {
		case STRICT_TYPE: mode_str = "strict"; break;
		case DYNAMIC_TYPE: mode_str = "dynamic"; break;
		case RANDOM_TYPE: mode_str = "random"; break;
		case ROUND_ROBIN_TYPE: mode_str = "round_robin"; break;
	}

	printf("=== proxychains-ng effective configuration ===\n");
	printf("chain: %s\n", mode_str);
	printf("chain_len: %u (max)\n", proxychains_max_chain);
	printf("dns: %s\n", rdns_resolver_string(proxychains_resolver));
	printf("quiet: %s\n", proxychains_quiet_mode ? "true" : "false");
	printf("tcp_read_timeout: %d ms\n", tcp_read_time_out);
	printf("tcp_connect_timeout: %d ms\n", tcp_connect_time_out);
	printf("remote_dns_subnet: %u\n", remote_dns_subnet);

	printf("localnets: %zu entries\n", num_localnet_addr);
	for(i = 0; i < num_localnet_addr; i++) {
		if(localnet_addr[i].family == AF_INET) {
			char buf[64], maskbuf[64];
			inet_ntop(AF_INET, &localnet_addr[i].in_addr, buf, sizeof(buf));
			inet_ntop(AF_INET, &localnet_addr[i].in_mask, maskbuf, sizeof(maskbuf));
			if(localnet_addr[i].port) {
				printf("  - %s:%u/%s\n", buf, localnet_addr[i].port, maskbuf);
			} else {
				printf("  - %s/%s\n", buf, maskbuf);
			}
		} else {
			char buf[128];
			inet_ntop(AF_INET6, &localnet_addr[i].in6_addr, buf, sizeof(buf));
			if(localnet_addr[i].port) {
				printf("  - [%s]:%u/%u\n", buf, localnet_addr[i].port, localnet_addr[i].in6_prefix);
			} else {
				printf("  - [%s]/%u\n", buf, localnet_addr[i].in6_prefix);
			}
		}
	}

	printf("dnat rules: %zu entries\n", num_dnats);
	for(i = 0; i < num_dnats; i++) {
		char src[32], dst[32];
		inet_ntop(AF_INET, &dnats[i].orig_dst, src, sizeof(src));
		inet_ntop(AF_INET, &dnats[i].new_dst, dst, sizeof(dst));
		printf("  - %s:%d -> %s:%d\n", src, dnats[i].orig_port, dst, dnats[i].new_port);
	}

	printf("proxies: %u entries\n", count);
	for(i = 0; i < count; i++) {
		char hostbuf[128];
		const char *type_str;
		inet_ntop(pd[i].ip.is_v6 ? AF_INET6 : AF_INET, 
		          pd[i].ip.is_v6 ? (void*)&pd[i].ip.addr.v6 : (void*)&pd[i].ip.addr.v4, 
		          hostbuf, sizeof(hostbuf));
		
		switch(pd[i].pt) {
			case SOCKS5_TYPE: type_str = "socks5"; break;
			case SOCKS4_TYPE: type_str = "socks4"; break;
			case HTTP_TYPE: type_str = "http"; break;
			case RAW_TYPE: type_str = "raw"; break;
			default: type_str = "unknown"; break;
		}
		
		printf("  - %s %s:%u user=%s\n", 
		       type_str, hostbuf, ntohs(pd[i].port), 
		       pd[i].user[0] ? pd[i].user : "(none)");
	}

	printf("=============================================\n");
}
