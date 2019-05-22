/*
   C port scanner
   */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <regex.h>

#include "net.h"
#include "time.h"
#include "common.h"
#include "threads.h"
#include "colors.h"

#define         PHSCAN_PROGNAME      "phscan"
#define         PHSCAN_SIMPLE        0
#define         PHSCAN_SUCCESS       0
#define         PHSCAN_ERROR         1
#define         PHSCAN_RANGE         2

#define         VERSION             0.2

#define FIXME "localhost"

static struct timeval g_elapsed;
static int g_color = 0;
static int g_socket_timeout = 100; //ms

// Defined in threads.h
// extern retval_t retvals[MAX_THREAD_COUNT];
// extern pthread_t working_threads[MAX_THREAD_COUNT];
// extern unsigned current_running_threads;

void usage(char *program)
{
    err(
            "USAGE: %s [hv|V] -p PORT1[[:-,]PORTN)] HOST1[/SUBNET | HOST2 ...])\n"
            "-c                     Show colorized output\n"
            "-h                     Show this help and exit\n"
            "-p <port[{:,-}range]>  Perform an IP address scanning on the specified port\n"
            "-t <timeout>           Set socket connection timeout in ms\n"
            "                       Defaults to: %d ms.\n"
            "-v                     Show version information and exit\n"
            "-V                     Enable verbose\n"
            "\nNote 1: The port range shall be applied using one the following formats: \"start:end\"\n"
            "\"start-end\" or \"start,end\"\n"
            "Note 2: Subnets shall be specified using CIDR notation: \"SUBNET/MASK\"\n\n"
            "Example usage 1: %s -p 20:30 -H 192.168.1.1\t\tDo a port scan from 20 to 30 on the given host\n"
            "Example usage 2: %s -p 80    -H 192.168.1.0/24\tDo a host scan in search for open port 80\n"
            "Example usage 3: %s -p 10,20 -H 192.168.1.0/24\tPerform both port and host scans\n"
            , program, g_socket_timeout, program, program, program );

}
void version(char *program)
{
    err("%s - version v%.2f, developed by eiger824\n",
            program, VERSION);
}

int check_optarg_valid(const char* str, char delim)
{
    char *tmp;
    if ((tmp = strchr(str, delim)) != NULL) // Range char was provided
    {
        if (tmp == str || tmp == str + strlen(str) + 1)
        {
            return PHSCAN_ERROR;
        }
        else
        {
            return PHSCAN_RANGE;
        }
    }
    else
    {
        if (!strlen(str)) return PHSCAN_ERROR;
        else return PHSCAN_SIMPLE;
    }
}

int parse_ports(const char* str, int* port_start, int* port_end)
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
            return PHSCAN_RANGE;
        return PHSCAN_SUCCESS;
    }

    if (regex_match(str, "^[0-9]+[[:blank:]]*([,-:][[:blank:]]*[0-9]+)?$") == 0)
    {
        delim = find_delim(str);
        *port_start = atoi(str);
        p = strchr(str, delim);
        *port_end = atoi(++p);
        if (verify_port(*port_start) || verify_port(*port_end))
            return PHSCAN_RANGE;
        return PHSCAN_SUCCESS;
    }

    return PHSCAN_RANGE;
}

int scan_hosts(int argc, char** argv, int opt_index, int port_start, int port_end)
{
    int i;
    int port;
    host_t** hosts;
    host_t** arr;
    host_t* h;

    if (argc - opt_index == 0 || port_start == -1 || port_end == -1)
    {
        err("Not enough input arguments: ");
        if (port_start == -1 || port_end == -1)
            err("Port or port range missing\n");
        else
            err("No hosts were provided for scanning\n");

        usage(PHSCAN_PROGNAME);
        return PHSCAN_ERROR;
    }

    dbg("Starting port scanning in range [%d-%d]\n", port_start, port_end);

    set_timer(&g_elapsed);
    // Loop through the hosts
    for (i = opt_index; i < argc; ++i)
    {
        // argv[i] can either be one of:
        //   => IP subnet  [no DNS]             [N elements]
        //   => IP address [no DNS]             [1 element ]
        //   => Host       [DNS lookup required][1 element ]
    
        // Iterate through these hosts
        hosts = build_hosts_list(argv[i]);
        arr = hosts;
        for (h = *arr; h; h = *++arr)
        {
            info("%s%s%s (%s%s%s):\n",
                    COLOR_IF(CYAN), h->hostname, COLOR_IF(RESET),
                    COLOR_IF(MAGENTA), h->ip, COLOR_IF(RESET));

            for (port = port_start; port <= port_end; ++port)
            {
                if (connect_to_host(h->ip, port, g_socket_timeout) != 0)
                    dbg("  %5d: closed\n", port);
                else
                    info("  %s%5d: open%s\n",
                            COLOR_IF(GREEN), port, COLOR_IF(RESET));
            }
        }
    }
    info("Done! Scanning took %.2f s.\n", get_elapsed_secs(&g_elapsed));

    free_host_list(hosts);

    return PHSCAN_SUCCESS;
}


int main(int argc , char **argv)
{
    int c;
    int port_start, port_end;

    port_start = -1;
    port_end = -1;

    // Allocate memory for host start and end
    while ((c = getopt(argc, argv, "chp:t:vV")) != -1)
    {
        switch (c)
        {
            case 'c':
                g_color = 1;
                break;
            case 'h':
                usage(PHSCAN_PROGNAME);
                exit(0);
            case 'p':
                if (parse_ports(optarg, &port_start, &port_end) == PHSCAN_ERROR)
                    die(usage, PHSCAN_PROGNAME, "Wrong port format\n");
                break;
            case 't':
                g_socket_timeout = atoi(optarg);
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
    return scan_hosts(argc, argv, optind, port_start, port_end);
} 
