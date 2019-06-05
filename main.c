/*
   C port scanner
   */
#include <stdio.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <regex.h>

#include "net/net.h"
#include "timings.h"
#include "common.h"
#include "colors.h"
#include "process.h"
#include "opts.h"

static struct timeval g_elapsed;

static void usage(char *program)
{
    err(
            "USAGE: %s [hv|V] -p PORT1[[:-,]PORTN)] HOST1[/SUBNET | HOST2 ...])\n"
            "-c                     Show colorized output\n"
            "                       Defaults to: %s\n"
            "-h                     Show this help and exit\n"
            "-j <threads>           Run the scan in parallel\n"
            "                       Note that for this machine, %d is the allowed maximum\n"
            "-p <port[{:,-}range]>  Perform an IP address scanning on the specified port\n"
            "-s <scan_type>         Perform the indicated technique when doing the port scanning\n"
            "                       Supported types:\n"
            "                         C => Full TCP connect() (3-way handshake)\n"
            "                         H => TCP Half open (SYN - SYN/ACK)\n"
            "                         I => ICMP echo request/reply\n"
            "                       The default, if not specified: C. Note that when using\n"
            "                       'H', the process must be run with elevated privileges\n"
            "                       or with the CAP_NET_RAW capability set\n"
            "-S                     When using the half open scan, spoof our IP address\n"
            "                       with a random IP\n"
            "-t <timeout>           Set socket connection timeout in ms\n"
            "                       Defaults to: %d ms\n"
            "-v                     Show version information and exit\n"
            "-V                     Enable verbose\n"
            "\nNote 1: The port range shall be applied using one the following formats: \"start:end\"\n"
            "\"start-end\" or \"start,end\"\n"
            "Note 2: Subnets shall be specified using CIDR notation: \"SUBNET/MASK\"\n\n"
            "Example usage 1: %s -p 20:30  192.168.1.1\t\tDo a port scan from 20 to 30 on the given host\n"
            "Example usage 2: %s -p 80     192.168.1.0/24\tDo a host scan in search for open port 80\n"
            "Example usage 3: %s -p 10,20  192.168.1.0/24\tPerform both port and host scans\n"
            , program, get_color() ? "enabled":"disabled",
            get_nprocs(), get_connect_timeout(), program, program, program );

}
static void version(char *program)
{
    err("%s - version v%.2f, developed by eiger824\n",
            program, PHSCAN_VERSION);
}

static int parse_scan_type(const char* str, scan_type_t* type)
{
    if (!str)
        return PHSCAN_ERROR;

    if (regex_match(str, "^[CHI]$") == 0)
    {
        switch (*str)
        {
            case 'C':
                *type = PHSCAN_TCP_CONNECT;
                break;
            case 'H':
                *type = PHSCAN_TCP_HALF_OPEN;
                break;
            case 'I':
                *type = PHSCAN_ICMP_PING;
                break;
            default:  /* Never reached */
                *type = PHSCAN_SCAN_TYPE_UNKNOWN;
                break;
        }

        return PHSCAN_SUCCESS;
    }

    return PHSCAN_ERROR;
}

static int verify_opts(int argc, int opt_index, scan_type_t s, int ports_set, int spoof)
{
    int ret = PHSCAN_SUCCESS;
    if (argc - opt_index == 0 || (s != PHSCAN_ICMP_PING && ports_set == -1))
    {
        err("Not enough input arguments: ");
        if (ports_set == -1)
            err("Port or port range missing\n");
        else
            err("No hosts were provided for scanning\n");

        usage(PHSCAN_PROGNAME);
        return PHSCAN_ERROR;
    }

    if (spoof && s != PHSCAN_TCP_HALF_OPEN)
    {
        err("IP address spoofing can only be used with the TCP half open scan technique\n");
        usage(PHSCAN_PROGNAME);
        return PHSCAN_ERROR;
    }

    if ((s == PHSCAN_TCP_HALF_OPEN || s == PHSCAN_ICMP_PING) && getuid() != 0)
    {
        err("Need to be root if this scan type is to be used\n");
        return PHSCAN_ERROR;
    }
    return ret;
}

static int scan_hosts(int argc, char** argv, int opt_index, const options_t* opts)
{
    char elapsed[128];
    int ret;

    net_t* net = net_create(opts->socket_timeout, opts->ip_spoofing, opts->thread_count);
    
    if (verify_opts(argc, opt_index, opts->s, opts->ports_set, opts->ip_spoofing) != PHSCAN_SUCCESS)
    {
        return -1;
    }

    if (net_build_tasks_list(net, argc, argv, opt_index) != PHSCAN_SUCCESS)
    {
        die(usage, PHSCAN_PROGNAME, "Error building\n");
    }

    start_timer(&g_elapsed);
    ret = process_hosts(opts->s);

    if ( ret != PHSCAN_SUCCESS)
    {
        err("Error scanning hosts\n");
    }
    else
    {
        stop_timer(&g_elapsed, elapsed);
        info("Done! Scanning took %s.\n", elapsed);
        // Print the hosts
        print_scan_results();
    }

    // Free up memory
    net_cleanup();

    return PHSCAN_SUCCESS;
}

int main(int argc , char **argv)
{
    int c, ports_set;
    port_t port_start, port_end;

    port_start = -1;
    port_end = -1;
    ports_set = -1;

    options_t* opt = options_create();
    options_set_default(opt);

    if (signal(SIGINT, signal_handler) != 0)
    {
        perror("signal() failed");
        exit(1);
    }

    // Allocate memory for host start and end
    while ((c = getopt(argc, argv, "chj:p:s:St:vV")) != -1)
    {
        switch (c)
        {
            case 'c':
                set_color(1);
                break;
            case 'h':
                usage(PHSCAN_PROGNAME);
                exit(0);
            case 'j':
                opt->thread_count = atoi(optarg);
                if (opt->thread_count < 1 || (int)opt->thread_count > get_nprocs())
                {
                    err("Invalid thread count (%d). Accepted range: [1-%d]\n",
                            opt->thread_count, get_nprocs());
                    exit(PHSCAN_ERROR);
                }
                break;
            case 'p':
                if (parse_ports(optarg, &port_start, &port_end) == PHSCAN_ERROR)
                    die(usage, PHSCAN_PROGNAME, "Wrong port format `%s'\n", optarg);
                add_port_range(port_start, port_end);
                ports_set = 1;
                break;
            case 's':
                if (parse_scan_type(optarg, &opt->s) == PHSCAN_ERROR)
                    die(usage, PHSCAN_PROGNAME, "Wrong scan type `%s'\n", optarg);
                break;
            case 'S':
                opt->ip_spoofing = true;
                break;
            case 't':
                opt->socket_timeout = atoi(optarg);
                break;
            case 'v':
                version(PHSCAN_PROGNAME);
                exit(0);
            case 'V':
                opt->verbose = true;
                info("Verbose is ON\n");
                break;
            default:
                usage(PHSCAN_PROGNAME);
                exit(PHSCAN_ERROR);
        }
    }

    // Positional argument: hosts
    int ret = scan_hosts(argc, argv, optind, opt);

    options_destroy(opt);

    return ret;
}
