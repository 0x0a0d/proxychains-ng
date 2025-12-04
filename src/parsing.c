/***************************************************************************
                          parsing.c  -  unified parsing module
                             -------------------
			    Shared parsing functions for proxy URLs, localnet,
			    and DNAT entries. Eliminates code duplication between
			    config file parsing and CLI parsing.
 ***************************************************************************/
/*     GPL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "parsing.h"
#include "argparse.h"  /* for MAX_CLI_STRING */

int detect_socks5h_in_list(const char *proxy_list) {
	if(!proxy_list || !*proxy_list) return 0;
	return (strstr(proxy_list, "socks5h://") != NULL);
}

int split_and_process(const char *str, token_callback_t callback, void *ctx) {
	char buffer[MAX_CLI_STRING];
	char *token, *saveptr;
	int count = 0;

	if(!str || !*str) return 0;

	strncpy(buffer, str, sizeof(buffer) - 1);
	buffer[sizeof(buffer) - 1] = 0;

	/* Replace semicolons with commas for uniform splitting */
	for(char *p = buffer; *p; p++) {
		if(*p == ';') *p = ',';
	}

	token = strtok_r(buffer, ",", &saveptr);
	while(token) {
		/* Trim leading whitespace */
		while(*token && isspace((unsigned char)*token)) token++;
		/* Trim trailing whitespace */
		char *end = token + strlen(token) - 1;
		while(end > token && isspace((unsigned char)*end)) *end-- = 0;

		if(*token) {
			if(callback(token, ctx) != 0) {
				count++;
			}
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	return count;
}

/*
 * Parse a proxy URL into proxy_data_ex structure.
 * 
 * Supports:
 *   socks5://host:port
 *   socks5://user:pass@host:port
 *   socks5h://host:port              (remote DNS flag set)
 *   socks4://host:port
 *   http://[user:pass@]host:port
 *   raw://host:port
 * 
 * Host can be numeric IP (v4/v6) or hostname.
 * Hostname is stored in pd_ex->hostname; caller must resolve it later.
 */
int parse_proxy_url(const char *url, proxy_data_ex *pd_ex) {
	const char *p;
	size_t next_token = 0, ul = 0, pl = 0, hl;
	char type[32], host[256];
	int port_n = 0;
	int is_socks5h = 0;

	if(!url || !*url) return 0;

	memset(pd_ex, 0, sizeof(*pd_ex));
	pd_ex->pd.ps = PLAY_STATE;

	/* Check protocol prefix */
	if(STR_STARTSWITH(url, "socks5h://")) {
		strcpy(type, "socks5");
		is_socks5h = 1;
		next_token = 10;
	} else if(STR_STARTSWITH(url, "socks5://")) {
		strcpy(type, "socks5");
		next_token = 9;
	} else if(STR_STARTSWITH(url, "socks4://")) {
		strcpy(type, "socks4");
		next_token = 9;
	} else if(STR_STARTSWITH(url, "http://")) {
		strcpy(type, "http");
		next_token = 7;
	} else if(STR_STARTSWITH(url, "raw://")) {
		strcpy(type, "raw");
		next_token = 6;
	} else {
		return 0;
	}

	/* Set remote DNS flag for socks5h */
	if(is_socks5h) {
		pd_ex->flags |= PROXY_FLAG_REMOTE_DNS;
	}

	/* Parse user:pass@host:port */
	const char *at = strrchr(url + next_token, '@');
	if(at) {
		/* socks4 doesn't support auth */
		if(!strcmp(type, "socks4")) return 0;
		
		p = strchr(url + next_token, ':');
		if(!p || p >= at) return 0;
		
		const char *u = url + next_token;
		ul = p - u;
		p++;
		pl = at - p;
		
		if(ul > 255 || pl > 255) return 0;
		
		memcpy(pd_ex->pd.user, u, ul);
		pd_ex->pd.user[ul] = 0;
		memcpy(pd_ex->pd.pass, p, pl);
		pd_ex->pd.pass[pl] = 0;
		next_token = (at - url) + 1;
	}

	/* Parse host:port - handle IPv6 brackets */
	const char *h = url + next_token;
	const char *port_sep = NULL;
	
	if(*h == '[') {
		/* IPv6 with brackets: [::1]:port */
		const char *bracket_end = strchr(h, ']');
		if(!bracket_end) return 0;
		
		hl = bracket_end - h - 1;  /* length without brackets */
		if(hl > 254) return 0;
		
		memcpy(host, h + 1, hl);
		host[hl] = 0;
		
		/* Port must follow bracket */
		if(bracket_end[1] == ':') {
			port_sep = bracket_end + 1;
		} else if(bracket_end[1] != '\0') {
			return 0;  /* invalid format */
		}
	} else {
		/* IPv4 or hostname or bare IPv6 */
		/* Find the last colon - for IPv6 without brackets, this is tricky */
		const char *last_colon = strrchr(h, ':');
		const char *first_colon = strchr(h, ':');
		
		if(last_colon && first_colon == last_colon) {
			/* Only one colon - IPv4:port or hostname:port */
			port_sep = last_colon;
			hl = port_sep - h;
		} else if(last_colon) {
			/* Multiple colons - IPv6 address */
			/* Try to find port: assume last segment after ':' is numeric */
			const char *maybe_port = last_colon + 1;
			int all_digits = 1;
			for(const char *c = maybe_port; *c; c++) {
				if(!isdigit((unsigned char)*c)) {
					all_digits = 0;
					break;
				}
			}
			if(all_digits && *maybe_port) {
				/* Last segment is port */
				port_sep = last_colon;
				hl = port_sep - h;
			} else {
				/* No port, entire string is IPv6 */
				hl = strlen(h);
			}
		} else {
			/* No colon at all - hostname without port */
			return 0;  /* port is required */
		}
		
		if(hl > 255) return 0;
		memcpy(host, h, hl);
		host[hl] = 0;
	}

	/* Parse port */
	if(!port_sep) return 0;  /* port is required */
	port_n = atoi(port_sep + 1);
	if(port_n <= 0 || port_n > 65535) return 0;

	/* Set proxy type */
	if(!strcmp(type, "http")) {
		pd_ex->pd.pt = HTTP_TYPE;
	} else if(!strcmp(type, "raw")) {
		pd_ex->pd.pt = RAW_TYPE;
	} else if(!strcmp(type, "socks4")) {
		pd_ex->pd.pt = SOCKS4_TYPE;
	} else if(!strcmp(type, "socks5")) {
		pd_ex->pd.pt = SOCKS5_TYPE;
	} else {
		return 0;
	}

	pd_ex->pd.port = htons((unsigned short)port_n);

	/* Try to parse as IP address */
	pd_ex->pd.ip.is_v6 = !!strchr(host, ':');
	
	if(1 == inet_pton(pd_ex->pd.ip.is_v6 ? AF_INET6 : AF_INET, 
	                  host, pd_ex->pd.ip.addr.v6)) {
		/* Numeric IP - we're done */
		pd_ex->hostname[0] = 0;
	} else {
		/* Hostname - store for later resolution */
		strncpy(pd_ex->hostname, host, sizeof(pd_ex->hostname) - 1);
		pd_ex->hostname[sizeof(pd_ex->hostname) - 1] = 0;
		/* Zero out IP - caller must resolve */
		memset(&pd_ex->pd.ip, 0, sizeof(pd_ex->pd.ip));
	}

	return 1;
}

/*
 * Parse a localnet specification string.
 * 
 * Formats:
 *   IPv4:        192.168.0.0/24 or 192.168.0.0/255.255.255.0
 *   IPv4+port:   192.168.0.0:8080/24
 *   IPv6:        fe80::/10
 *   IPv6+port:   [fe80::]:8080/10
 */
int parse_localnet_entry(const char *spec, localaddr_arg *out) {
	char addr_port[64], addr[64], netmask[32];
	char colon, extra, right_bracket[2];
	unsigned short port = 0, prefix;
	int family, n, valid;
	const char *p;

	if(!spec || !*spec) return 0;

	memset(out, 0, sizeof(*out));

	/* Split into addr[:port] and /mask */
	if(sscanf(spec, "%53[^/]/%15s", addr_port, netmask) != 2) {
		return 0;
	}

	/* Detect address family and parse addr:port */
	p = strchr(addr_port, ':');
	if(!p || p == strrchr(addr_port, ':')) {
		/* No colon or single colon: IPv4 */
		family = AF_INET;
		n = sscanf(addr_port, "%15[^:]%c%5hu%c", addr, &colon, &port, &extra);
		valid = n == 1 || (n == 3 && colon == ':');
	} else if(addr_port[0] == '[') {
		/* Bracketed IPv6: [addr]:port */
		family = AF_INET6;
		n = sscanf(addr_port, "[%45[^][]%1[]]%c%5hu%c", addr, right_bracket, &colon, &port, &extra);
		valid = n == 2 || (n == 4 && colon == ':');
	} else {
		/* Bare IPv6 without brackets */
		family = AF_INET6;
		valid = sscanf(addr_port, "%45[^][]%c", addr, &extra) == 1;
	}

	if(!valid) return 0;

	out->family = family;
	out->port = port;

	/* Parse address */
	if(family == AF_INET) {
		if(inet_pton(family, addr, &out->in_addr) <= 0) return 0;
	} else {
		if(inet_pton(family, addr, &out->in6_addr) <= 0) return 0;
	}

	/* Parse netmask */
	if(family == AF_INET && strchr(netmask, '.')) {
		/* Dotted decimal mask */
		if(inet_pton(family, netmask, &out->in_mask) <= 0) return 0;
	} else {
		/* Prefix length */
		if(sscanf(netmask, "%hu%c", &prefix, &extra) != 1) return 0;
		
		if(family == AF_INET) {
			if(prefix > 32) return 0;
			out->in_mask.s_addr = htonl(0xFFFFFFFFu << (32u - prefix));
		} else {
			if(prefix > 128) return 0;
			out->in6_prefix = prefix;
		}
	}

	return 1;
}

/*
 * Parse a DNAT rule specification.
 * 
 * Format: src[-src_port]-dst[-dst_port]  (dash separated)
 * 
 * Examples:
 *   1.1.1.1-2.2.2.2              (IP only)
 *   1.1.1.1:80-2.2.2.2           (src with port)
 *   1.1.1.1:80-2.2.2.2:443       (both with ports)
 *   1.1.1.1-2.2.2.2:443          (dst with port)
 */
int parse_dnat_entry(const char *spec, dnat_arg *out) {
	char src[32], dst[32];
	char src_addr[16], src_port_str[8] = {0};
	char dst_addr[16], dst_port_str[8] = {0};
	const char *dash;

	if(!spec || !*spec) return 0;

	memset(out, 0, sizeof(*out));

	/* Find the dash separator between src and dst */
	dash = strchr(spec, '-');
	if(!dash) return 0;

	/* Copy src part */
	size_t src_len = dash - spec;
	if(src_len >= sizeof(src)) src_len = sizeof(src) - 1;
	memcpy(src, spec, src_len);
	src[src_len] = 0;

	/* Copy dst part */
	strncpy(dst, dash + 1, sizeof(dst) - 1);
	dst[sizeof(dst) - 1] = 0;

	/* Parse src address:port */
	(void)sscanf(src, "%15[^:]:%5s", src_addr, src_port_str);
	
	/* Parse dst address:port */
	(void)sscanf(dst, "%15[^:]:%5s", dst_addr, dst_port_str);

	/* Validate and convert addresses */
	if(inet_pton(AF_INET, src_addr, &out->orig_dst) <= 0) return 0;
	if(inet_pton(AF_INET, dst_addr, &out->new_dst) <= 0) return 0;

	/* Convert ports */
	out->orig_port = src_port_str[0] ? (short)atoi(src_port_str) : 0;
	out->new_port = dst_port_str[0] ? (short)atoi(dst_port_str) : 0;

	return 1;
}
