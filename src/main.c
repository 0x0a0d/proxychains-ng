/*   (C) 2011, 2012 rofl0r
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef IS_MAC
#define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>

#include "argparse.h"
#include "common.h"
#include "version.h"

static int usage(char **argv) {
	printf("\nUsage: %s [options] program [arguments]\n\n", argv[0]);

	printf("Options:\n");
	printf("Config File:\n");
	printf("  -f, --config-file <path>     Use alternative config file\n");
	printf("      --ignore-config-file     Ignore config file completely\n\n");

	printf("Chain Mode:\n");
	printf("  -c, --chain [mode[:len]]     Set chain mode\n");
	printf("                               s|strict (default), d|dynamic,\n");
	printf("                               rr|round_robin, rd|random\n");
	printf("                               Optional :N for chain length (e.g. "
				 "rr:2)\n");
	printf("  -l, --chain-len <N>          Set chain length\n\n");

	printf("DNS Mode:\n");
	printf("  -d, --dns [mode]             Set DNS mode\n");
	printf("                               proxy (default), old, off\n");
	printf(
			"                               IP:PORT or [IPv6]:PORT for daemon\n\n");

	printf("Proxies (repeatable, URL format only):\n");
	printf("  -P, --proxy <url>            Add proxy (repeatable)\n");
	printf("                               Format: "
				 "protocol://[user:pass@]host:port\n");
	printf("                               Protocols: http, socks4, socks5, "
				 "socks5h, raw\n\n");

	printf("Network:\n");
	printf(
			"  -n, --localnet <spec>        Add localnet exclusion (repeatable)\n");
	printf("      --dnat <src-dst>         Add DNAT rule (repeatable)\n");
	printf("                               Format: src-dst (dash separator)\n");
	printf("  -S, --remote-dns-subnet <N>  Remote DNS subnet (0-255)\n\n");

	printf("Timeouts:\n");
	printf("  -R, --tcp-read-timeout <ms>  TCP read timeout\n");
	printf("  -T, --tcp-connect-timeout <ms> TCP connect timeout\n\n");

	printf("Output:\n");
	printf("  -q, --quiet                  Quiet mode (no output)\n");
	printf("      --no-quiet               Disable quiet mode\n");
	printf("  -D, --debug-level <N>        Debug level (0=silent, 1=basic, "
				 "2=verbose)\n");
	printf("  -v, --version                Print version and exit\n");
	printf("      --show-config            Print effective configuration then "
				 "exit. Program/args optional\n\n");

	printf("Help:\n");
	printf("  -h, --help                   Show this help\n\n");

	printf("Examples:\n");
	printf("# Simple: run curl through the default config file\n");
	printf("  %s curl https://example.com\n", argv[0]);
	printf("# Use a specific config file and run quietly\n");
	printf("  %s -q -f /etc/proxychains.conf curl https://example.com\n",
				 argv[0]);
	printf("# Force chain type and DNS via CLI\n");
	printf("  %s -c strict -d proxy curl https://example.com\n", argv[0]);
	printf("# Add a proxy on the command-line (repeatable)\n");
	printf("  %s -P socks5://127.0.0.1:1080 -P http://proxy.local:8080 curl "
				 "https://example.com\n",
				 argv[0]);
	printf("# Ignore config file and provide proxy list via CLI\n");
	printf("  %s --ignore-config-file -P socks5://tor:9050 curl "
				 "https://example.com\n",
				 argv[0]);
	printf("# Show the merged configuration (no program needed) and exit\n");
	printf("  %s --show-config\n", argv[0]);
	printf("# Show configuration based on CLI and file and exit (program/args "
				 "optional)\n");
	printf("  %s --show-config -f /etc/proxychains.conf -P "
				 "socks5://127.0.0.1:1080\n",
				 argv[0]);
	printf("# Print program version and exit\n");
	printf("  %s -v\n", argv[0]);
	printf("# Example with localnet and DNAT entries (override via CLI)\n");
	printf(
			"  %s --ignore-config-file -n 192.168.0.0/16 -n 10.0.0.0/8 --dnat "
			"1.1.1.1:80-2.2.2.2:443 -P socks5://127.0.0.1:1080 curl http://1.1.1.1\n",
			argv[0]);
	printf("# Configure timeouts and remote DNS subnet via CLI\n");
	printf("  %s -R 5000 -T 3000 -S 224 -P socks5://127.0.0.1:1080 curl "
				 "https://example.com\n\n",
				 argv[0]);

	printf("Priority: argv > env > config file\n\n");

	return EXIT_FAILURE;
}

static const char *dll_name = DLL_NAME;

static char own_dir[256];
static const char *dll_dirs[] = {
#ifndef SUPER_SECURE /* CVE-2015-3887 */
	".",
#endif
	own_dir,
	LIB_DIR,
	"/lib",
	"/usr/lib",
	"/usr/local/lib",
	"/lib64",
	NULL
};

static void set_own_dir(const char *argv0) {
	size_t l = strlen(argv0);
	while(l && argv0[l - 1] != '/')
		l--;
	if(l == 0 || l >= sizeof(own_dir))
#ifdef SUPER_SECURE
		memcpy(own_dir, "/dev/null/", 11);
#else
		memcpy(own_dir, ".", 2);
#endif
	else {
		memcpy(own_dir, argv0, l - 1);
		own_dir[l] = 0;
	}
}

int main(int argc, char *argv[]) {
	char *path = NULL;
	char buf[256];
	char pbuf[256];
	int start_argv;
	size_t i;
	const char *prefix = NULL;
	cli_options opts;
	int parse_result;

	/* Parse arguments */
	parse_result = parse_arguments(argc, argv, &opts, &start_argv);
	if (parse_result == 2) {
		return usage(argv); /* Help requested */
	}
	if (parse_result == 3) {
		/* Version was requested; print and exit */
		printf("%s\n", VERSION);
		return EXIT_SUCCESS;
	}
	if(parse_result != 0) {
		return usage(argv); /* Parse error */
	}

	/* Handle config file */
	if (!opts.ignore_config_file) {
		path = get_config_path(opts.config_file_path, pbuf, sizeof(pbuf));
		if(!opts.quiet_mode)
			fprintf(stderr, LOG_PREFIX "config file found: %s\n", path);

	/* Set PROXYCHAINS_CONF_FILE to get proxychains lib to use new config file. */
		setenv(PROXYCHAINS_CONF_FILE_ENV_VAR, path, 1);
	} else {
		if (!opts.quiet_mode)
			fprintf(stderr, LOG_PREFIX "ignoring config file\n");
	}

	/* Serialize CLI options to environment variables */
	serialize_cli_options_to_env(&opts);

	/* Set quiet mode */
	if(opts.quiet_mode)
		setenv(PROXYCHAINS_QUIET_MODE_ENV_VAR, "1", 1);


	// search DLL

	Dl_info dli;
	dladdr(own_dir, &dli);
	set_own_dir(dli.dli_fname);

	i = 0;

	while(dll_dirs[i]) {
		snprintf(buf, sizeof(buf), "%s/%s", dll_dirs[i], dll_name);
		if(access(buf, R_OK) != -1) {
			prefix = dll_dirs[i];
			break;
		}
		i++;
	}

	if(!prefix) {
		fprintf(stderr, "couldnt locate %s\n", dll_name);
		return EXIT_FAILURE;
	}
	if(!opts.quiet_mode)
		fprintf(stderr, LOG_PREFIX "preloading %s/%s\n", prefix, dll_name);

#if defined(IS_MAC) || defined(IS_OPENBSD)
#define LD_PRELOAD_SEP ":"
#else
/* Dynlinkers for Linux and most BSDs seem to support space
   as LD_PRELOAD separator, with colon added only recently.
   We use the old syntax for maximum compat */
#define LD_PRELOAD_SEP " "
#endif

#ifdef IS_MAC
	putenv("DYLD_FORCE_FLAT_NAMESPACE=1");
#define LD_PRELOAD_ENV "DYLD_INSERT_LIBRARIES"
#else
#define LD_PRELOAD_ENV "LD_PRELOAD"
#endif
	char *old_val = getenv(LD_PRELOAD_ENV);
	snprintf(buf, sizeof(buf), LD_PRELOAD_ENV "=%s/%s%s%s",
	         prefix, dll_name,
	         /* append previous LD_PRELOAD content, if existent */
	         old_val ? LD_PRELOAD_SEP : "",
	         old_val ? old_val : "");
	putenv(buf);
	/* If no program was provided, but --show-config was set, execute a helper to
		 load the preloaded library so it can print the configuration and exit.

					 Rationale and behavior:
					 - We try to exec the standard helper `true` (which is usually present
		 in PATH). This runs a short binary that immediately exits; the LD_PRELOAD
		 (or equivalent) will run the library constructor before the helper
		 executes, ensuring the config is printed by the library.
					 - If `true` isn't available (path might be minimal or on POSIX
		 systems where it's missing), we fall back to exec'ing the current program
		 (argv[0]) with no arguments. This also causes the runtime to load our
		 shared library (via LD_PRELOAD) and the constructor will print the
		 configuration. The exec will only return if it fails.

					 Note: Executing the current program again (no args) is safe because
		 the library constructor will print the config and exit; main won't be run
		 (or will exit quickly) because the constructor calls _exit(0) in
		 `get_chain_data()` when --show-config is set.
	*/
	if (start_argv >= argc && opts.has_show_config && opts.show_config) {
		/* Try the common helper 'true' first */
		char *true_argv[2] = {"true", NULL};
		execvp(true_argv[0], true_argv);
		/* If we get here, execvp failed; try exec'ing this program itself with no
		 * args */
		if (errno != ENOENT) {
			/* If the exec of 'true' failed for any reason other than missing binary,
			 * report it */
			fprintf(stderr, "proxychains: helper exec failed ('%s'): ", true_argv[0]);
			perror("");
		}
		/* Try to run the launcher itself with argc==1 (argv[0] only). This will
			 still run the library constructor (LD_PRELOAD) and print the config as
			 requested. */
		char *self_argv[2] = {argv[0], NULL};
		execvp(self_argv[0], self_argv);
		/* If we reach here, exec failed; print a helpful error and exit */
		fprintf(stderr, "proxychains: can't load helper or re-exec self ('%s').",
						self_argv[0]);
		perror(" (hint: check PATH and that the executable exists)");
		return EXIT_FAILURE;
	}

	execvp(argv[start_argv], &argv[start_argv]);
	fprintf(stderr, "proxychains: can't load process '%s'.", argv[start_argv]);
	perror(" (hint: it's probably a typo)");

	return EXIT_FAILURE;
}
