/***************************************************************************
                          parsing.h  -  unified parsing module
                             -------------------
			    Shared parsing functions for proxy URLs, localnet,
			    and DNAT entries. Eliminates code duplication between
			    config file parsing and CLI parsing.
 ***************************************************************************/
/*     GPL */

#ifndef PARSING_H
#define PARSING_H

#include <stddef.h>
#include <netinet/in.h>
#include "core.h"

/* Proxy parsing flags */
#define PROXY_FLAG_REMOTE_DNS  0x01  /* socks5h:// - request remote DNS resolution */

/* Extended proxy_data with additional metadata */
typedef struct {
	proxy_data pd;
	unsigned int flags;           /* PROXY_FLAG_* bits */
	char hostname[256];           /* Original hostname if non-numeric */
} proxy_data_ex;

/**
 * Parse a proxy URL string into proxy_data structure.
 * 
 * Supported formats:
 *   socks5://host:port
 *   socks5://user:pass@host:port
 *   socks5h://host:port              (remote DNS)
 *   socks4://host:port
 *   http://host:port
 *   http://user:pass@host:port
 *   raw://host:port
 * 
 * The host can be:
 *   - IPv4 address (e.g., 127.0.0.1)
 *   - IPv6 address (e.g., ::1 or with brackets [::1])
 *   - Hostname (e.g., proxy.example.com)
 * 
 * When hostname is used:
 *   - pd->hostname will contain the original hostname
 *   - pd->pd.ip will be zeroed (needs DNS resolution later)
 *   - Caller is responsible for resolving the hostname
 * 
 * @param url       Proxy URL string
 * @param pd_ex     Output: parsed proxy data (extended)
 * @return          1 on success, 0 on error
 */
int parse_proxy_url(const char *url, proxy_data_ex *pd_ex);

/**
 * Parse a localnet specification string.
 * 
 * Supported formats:
 *   IPv4:        192.168.0.0/24 or 192.168.0.0/255.255.255.0
 *   IPv4+port:   192.168.0.0:8080/24
 *   IPv6:        fe80::/10 or 2001:db8::/32
 *   IPv6+port:   [fe80::]:8080/10
 * 
 * @param spec      Localnet specification string
 * @param out       Output: parsed localnet entry
 * @return          1 on success, 0 on error
 */
int parse_localnet_entry(const char *spec, localaddr_arg *out);

/**
 * Parse a DNAT rule specification string.
 * 
 * Supported formats:
 *   src_ip-dst_ip                     (e.g., 1.1.1.1-2.2.2.2)
 *   src_ip:port-dst_ip                (e.g., 1.1.1.1:80-2.2.2.2)
 *   src_ip:port-dst_ip:port           (e.g., 1.1.1.1:80-2.2.2.2:443)
 *   src_ip-dst_ip:port                (e.g., 1.1.1.1-2.2.2.2:443)
 * 
 * Note: Currently IPv4 only.
 * 
 * @param spec      DNAT specification string (dash separator)
 * @param out       Output: parsed DNAT entry
 * @return          1 on success, 0 on error
 */
int parse_dnat_entry(const char *spec, dnat_arg *out);

/**
 * Callback function type for split_and_process.
 * 
 * @param token     Trimmed token string (non-empty)
 * @param ctx       User-provided context pointer
 * @return          Non-zero if token was successfully processed, 0 otherwise
 */
typedef int (*token_callback_t)(const char *token, void *ctx);

/**
 * Split a string by comma or semicolon and call callback for each token.
 * 
 * Tokens are trimmed of leading/trailing whitespace.
 * Empty tokens are skipped.
 * 
 * @param str       Input string (comma/semicolon separated)
 * @param callback  Function to call for each token
 * @param ctx       User context passed to callback
 * @return          Number of successfully processed tokens
 */
int split_and_process(const char *str, token_callback_t callback, void *ctx);

/**
 * Detect if any proxy in a comma-separated list uses socks5h:// protocol.
 * 
 * @param proxy_list  Comma/semicolon separated proxy URLs
 * @return            1 if socks5h found, 0 otherwise
 */
int detect_socks5h_in_list(const char *proxy_list);

/**
 * Check if a string starts with a literal prefix.
 * 
 * @param str       String to check
 * @param prefix    Literal prefix
 * @param prefix_len Length of prefix (use sizeof(lit)-1 for literals)
 * @return          1 if matches, 0 otherwise
 */
#define STR_STARTSWITH(str, lit) (!strncmp((str), (lit), sizeof(lit)-1))

#endif /* PARSING_H */
