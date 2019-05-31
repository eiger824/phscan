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

static struct timeval g_elapsed;
static int g_threads = 1;

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

    if (regex_match(str, "^[CH]$") == 0)
    {
        switch (*str)
        {
            case 'C':
                *type = PHSCAN_TCP_CONNECT; 
                break;
            case 'H':
                *type = PHSCAN_TCP_HALF_OPEN;
                break;
            default:  /* Never reached */
                *type = PHSCAN_SCAN_TYPE_UNKNOWN;
                break;
        }

        return PHSCAN_SUCCESS;
    }

    return PHSCAN_ERROR;
}

static int parse_ports(const char* str, int* port_start, int* port_end)
{
    char delim;
    char* p;
    // Input will be in 'str'
    // Output should be a port start and end
    // In case a single port is provided => port_start = port_end

    if (regex_match(str, "^[0-9]+$") == 0)
    {
        // Simplest case, no ranges, single port
        *port_start = atoi(str);
        *port_end = *port_start; 
        if (verify_port(*port_start) || verify_port(*port_end))
            return PHSCAN_ERROR;
        return PHSCAN_SUCCESS;
    }

    srand(time(NULL));

    if (regex_match(str, "^[0-9]+[[:blank:]]*([,-:][[:blank:]]*[0-9]+)?$") == 0)
    {
        delim = find_delim(str);
	if (delim != ',' && delim != '-' && delim != ':')
	    return PHSCAN_ERROR;

        *port_start = atoi(str);
        p = strchr(str, delim);
        *port_end = atoi(++p);
        if (verify_port(*port_start) || verify_port(*port_end))
            return PHSCAN_ERROR;
        return PHSCAN_SUCCESS;
    }

    return PHSCAN_ERROR;
}

static int scan_hosts(int argc, char** argv, int opt_index, int ports_set, scan_type_t s, int spoof)
{
    char elapsed[128];
    if (argc - opt_index == 0 || ports_set == -1)
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

    set_spoofing(spoof);

    if (build_tasks_list(argc, argv, opt_index) != PHSCAN_SUCCESS)
    {
        die(usage, PHSCAN_PROGNAME, "Error building\n");
    }

    start_timer(&g_elapsed);
    process_hosts(s);
    stop_timer(&g_elapsed, elapsed);

    info("Done! Scanning took %s.\n", elapsed);

    // Print the hosts
    print_scan_results();

    net_cleanup();

    return PHSCAN_SUCCESS;
}

int main(int argc , char **argv)
{
    int c, port_start, port_end, ports_set, ip_spoof = 0;
    scan_type_t s = PHSCAN_TCP_CONNECT;

    port_start = -1;
    port_end = -1;
    ports_set = -1;


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
                err("[threads] => FEATURE NOT YET SUPPORTED. Running with 1 thread\n");
                g_threads = atoi(optarg);
                if (g_threads < 0 || g_threads > get_nprocs())
                {
                    err("Invalid thread count. Accepted range: [1-%d]\n",
                            get_nprocs());
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
                if (parse_scan_type(optarg, &s) == PHSCAN_ERROR)
                    die(usage, PHSCAN_PROGNAME, "Wrong scan type `%s'\n", optarg);
                break;
            case 'S':
                ip_spoof = 1;
                break;
            case 't':
                set_connect_timeout(atoi(optarg));
                break;
            case 'v':
                version(PHSCAN_PROGNAME);
                exit(0);
            case 'V':
                set_verbose(1);
                info("Verbose is ON\n");
                break;
            default:
                usage(PHSCAN_PROGNAME);
                exit(PHSCAN_ERROR);
        }
    }

    // Positional argument: hosts
    return scan_hosts(argc, argv, optind, ports_set, s, ip_spoof);
} 
