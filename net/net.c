#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif  /* _DEFAULT_SOURCE */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <netdb.h>
#include <regex.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "scan/tcpconnect.h"
#include "scan/tcphalfopen.h"
#include "scan/icmpping.h"

#include "common.h"
#include "colors.h"
#include "progress.h"
#include "threads.h"

static int g_socket_timeout = 100; //ms
static int g_spoof_ip = 0;
static size_t g_thread_count = 1; // default
static struct port_range* g_port_ranges = NULL;
static size_t g_range_idx = 0;
static struct connection* g_conns;
static size_t g_conn_count = 0;

int bits_2_ipaddr(uint32_t ipaddr_bits, char *ip)
{
    uint8_t first = ipaddr_bits >> 24;
    uint8_t second = ipaddr_bits >> 16;
    uint8_t third = ipaddr_bits >> 8;
    uint8_t last = ipaddr_bits;

    if (!ip)
        return 1;

    sprintf(ip, "%d.%d.%d.%d", first, second, third, last);
    strcat(ip, "\0");

    return 0;
}

uint32_t ipaddr_2_bits(char *ip)
{
    char* token;
    char orig[1024];
    uint32_t out = 0;

    if (!ip)
        return 0;

    strcpy(orig, ip);

    // First token
    token = strtok(orig, ".");
    out |= ((uint32_t)atoi(token) << 24);
    // Second token
    token = strtok(NULL, ".");
    out |= ((uint32_t)atoi(token) << 16);
    // Third token
    token = strtok(NULL, ".");
    out |= ((uint32_t)atoi(token) << 8);
    // Fourth token
    token = strtok(NULL, ".");
    out |= (uint32_t)atoi(token) ;

    return out;
}

int do_dns_lookup(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        err("%s: %s\n", hostname, hstrerror(h_errno));
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}

static size_t get_total_host_count(int argc, char* argv[], int opt_index)
{
    int i;
    size_t total = 0;
    size_t n;
    for (i = opt_index; i < argc; ++i)
    {
        if ( is_ip(argv[i]) == 0)
            total++;
        else if ( is_subnet(argv[i]) == 0)
        {
            compute_ip_range(argv[i], NULL, &n);
            total += n;
        }
        else
            total++;
    }
    return total;
}

static size_t get_total_port_count()
{
    size_t total = 0;
    size_t i,j;
    struct port_range* r;
    for (i = 0; i < g_range_idx; ++i)
    {
        r = &g_port_ranges[i];
        for (j = r->port_start; j<= r->port_stop; ++j)
            total++;
    }
    return total;
}

static char** build_host_list(size_t n, int argc, char** argv, int optidx)
{
    int i;
    char** ips;
    char ip_start[16], ip_current[16];
    size_t j, k, current = 0;
    uint32_t ip_start_bits;

    ips = (char**) malloc(sizeof (ips) * (n + 1));
    for (j = 0; j < n; ++j)
    {
        *(ips + j) = (char*) malloc (sizeof(char) * 16);
    }

    for (i = optidx; i < argc; ++i)
    {
        if (is_ip(argv[i]) == 0) //IP
        {
            strcpy(*(ips + current++), argv[i]);
        }
        else if (is_subnet(argv[i]) == 0) //subnet in CIDR
        {
            if (compute_ip_range(argv[i], ip_start, &k) != 0)
            {
                return NULL;
            }
            ip_start_bits = ipaddr_2_bits(ip_start);
            for (j = 0; j < k; ++j)
            {
                // Translate this numeric repr into a readable IP address
                bits_2_ipaddr(ip_start_bits + j, ip_current);
                strcpy(*(ips + current++), ip_current);
            }
        }
        else //hostname
        {
            strcpy(*(ips + current++), argv[i]); 
        }
    }

    ips[current] = NULL;
    return ips;
}

static port_t* build_port_list(size_t n)
{
    port_t* out;
    size_t i, j, current = 0;
    struct port_range* r;

    if (n > 0)
    {
        out = (port_t*) malloc(sizeof(port_t) * n);
        for (i = 0; i < g_range_idx; ++i)
        {
            r = &g_port_ranges[i];
            for (j = r->port_start; j<= r->port_stop; ++j)
                out[current++] = j;
        }
    }
    else
    {
        out = (port_t*) malloc(sizeof(port_t));
        out[0] = 0;
    }

    return out;
}

int build_tasks_list(int argc, char** argv, int opt_index)
{
    int ret;
    struct connection *current;
    size_t port_count, ip_count, i, count, k=0;
    char **host_list, **c, *host;
    char rangestr[1024], resolved[16];
    port_t* port_list;

    ip_count = get_total_host_count(argc, argv, opt_index);
    port_count = get_total_port_count();

    host_list = build_host_list(ip_count, argc, argv, opt_index);
    c = host_list;
    port_list = build_port_list(port_count);

    port_count = port_count == 0 ? 1 : port_count;

    // Total number of tasks: #hosts * #ports
    count = ip_count * port_count;
    g_conn_count = count;

    get_range_str(rangestr);
    dbg("Starting port scanning in range(s) %s, %zu connection%s\n",
            rangestr, count, count > 1 ? "s" : "");

    ret = 0;
    g_conns = (struct connection* ) malloc (sizeof(struct connection) * count);

    for (host = *c; host; host = *++c)
    {
        for (i = 0; i < port_count; ++i)
        {
            current = &g_conns[k++];

            // If the current host needs DNS, do it now
            if (is_ip(host) != 0)
            {
                if ( ( ret = do_dns_lookup(host, resolved)) != 0 )
                {
                    host = NULL;
                    i = port_count;
                    break;
                }
                strcpy(current->ip, resolved);
                strcpy(current->hostname, host);
            }
            else
            {
                strcpy(current->ip, host);
                strcpy(current->hostname, host);
            }
            current->pinfo.portno = port_list[i];
            current->pinfo.status = PHSCAN_PORT_CLOSED;
            current->host_status = PHSCAN_HOST_DOWN;
        }
    }
    // Free the unneeded host and port lists
    free(port_list);
    c = host_list;
    for (host = *c; host; host = *++c)
    {
        free(host);
    }
    free(host_list);

    return ret;
}

int is_ip(char* str)
{
    return regex_match(str,
            "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))"
            "$"
            );
}

int is_subnet(char* str)
{
    return regex_match(str,
            "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))"
            "(/[0-9]+)?"
            "$"
            );
}

int compute_ip_range(char* str, char* ip_start, size_t* count)
{
    // Str: assumed to be a subnet
    // Let's get the count
    char* sep;
    int subnet;
    char ip[16];

    sep  = strchr(str, '/');
    subnet = atoi(++sep);

    if (subnet < 0 || subnet > 32)
        return 1;

    // Now that we have a valid subnet, count can easily be obtained
    *count = pow(2, 32 - subnet);

    char* to = strchr(str, '/');
    // Copy the provided IP address
    memcpy(ip, str, to - str);
    ip[to - str] = '\0';
    uint32_t bits = ipaddr_2_bits(ip);
    uint32_t subnet_bits = (0xffffffff << (32 - subnet));
    bits &= subnet_bits;

    if (ip_start)
        bits_2_ipaddr(bits, ip_start);

    return 0;
}

int process_hosts(scan_type_t scan_type)
{
    /* Each scanning technique has its own implementation
     * , but everyone takes the same arguments: the array
     * containing the tasks (connections) to perform, the
     * number of such tasks and the amount of threads to
     * use
     * */
    int (*task_handler)(struct connection*, size_t, int);

    switch (scan_type)
    {
        case PHSCAN_TCP_CONNECT:
            set_socket_timeout(g_socket_timeout);
            task_handler = tcpconnect_run_tasks;
            break;
        case PHSCAN_TCP_HALF_OPEN:
            set_ip_spoofing(g_spoof_ip);
            task_handler = tcphalfopen_run_tasks;
            break;
        case PHSCAN_ICMP_PING:
            task_handler = icmp_run_tasks;
            break;
        default:
            err("Unknown scan type, aborting\n");
            return PHSCAN_ERROR;
    }

    return task_handler(g_conns, g_conn_count, g_thread_count);
}

void print_scan_results()
{
    size_t i;
    port_t port;
    int status;
    struct connection* h;
    int new_host = 0;
    char* oldhost = NULL;

    for (i = 0; i < g_conn_count; ++i)
    {
        h = &g_conns[i];
        if (oldhost == NULL)
        {
            oldhost = h->ip;
            new_host = 1;
        }
        else
        {
            new_host = strcmp(h->ip, oldhost);
            oldhost = h->ip;
        }
        if (new_host)
        {
            info("%s%s%s (%s%s%s) [host %s]:\n",
                    COLOR_IF(CYAN), h->hostname, COLOR_IF(RESET),
                    COLOR_IF(MAGENTA), h->ip, COLOR_IF(RESET),
                    h->host_status == PHSCAN_HOST_UP ? "UP" : "DOWN");
        }

        port = h->pinfo.portno;
        if (port != 0)
        {
            status = h->pinfo.status;
            if (status != PHSCAN_PORT_OPEN)
                dbg("  %5d: closed\n", port);
            else
                info("  %s%5d: open%s\n",
                        COLOR_IF(GREEN), port, COLOR_IF(RESET));
        }
    }
}

int get_local_ip(const char* iface, char* ip)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];
    int found = 0;

    if (!ip)
        return 1;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (iface != NULL && strcmp(ifa->ifa_name, iface) != 0)
            continue;
        if (iface == NULL && strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        if (family == AF_INET || family == AF_INET6)
        {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }

            // Success! We found an IP for this interface, break now from loop
            strcpy(ip, host);
            found = 1;
            break;
        } 
    }

    freeifaddrs(ifaddr);

    if (found != 1)
        strcpy(ip, "??");

    return !found;
}

void set_connect_timeout(int timeout)
{
    g_socket_timeout = timeout;
}

int get_connect_timeout()
{
    return g_socket_timeout;
}

void set_spoofing(int spoof)
{
    g_spoof_ip = spoof;
}

void set_thread_count(size_t n)
{
    g_thread_count = n;
}

void add_port_range(port_t start, port_t stop)
{
    struct port_range* r;
    port_t tmp;
    if (g_range_idx == 0)
    {
        g_port_ranges =
            (struct port_range*) malloc(sizeof (struct port_range) * 1024);
    }
    r = &g_port_ranges[g_range_idx++];
    if (stop < start)
    {
        tmp = start;
        start = stop;
        stop = tmp;
    }
    r->port_start = start;
    r->port_stop = stop;
}

void free_task_list(struct connection* conns)
{
    if (!conns)
        return;

    free(conns);
}

void free_port_ranges()
{
    if (g_port_ranges == NULL)
        return;
    free(g_port_ranges);
}

void print_port_ranges()
{
    size_t i;
    for (i = 0; i < g_range_idx; ++i)
    {
        printf("[%d - %d]\n", g_port_ranges[i].port_start, g_port_ranges[i].port_stop);
    }
}

void get_range_str(char* str)
{
    size_t i;
    char current_range[16];
    struct port_range* r;
    memset(str, 0, 1024);
    if (!str)
        return;
    for (i = 0; i < g_range_idx; ++i)
    {
        r = &g_port_ranges[i];
        if (r->port_start < r->port_stop)
            sprintf(current_range, "[%d-%d]%s",
                    r->port_start, r->port_stop, i < g_range_idx - 1 ? ", " : "");
        else
            sprintf(current_range, "[%d]%s", r->port_start, i < g_range_idx - 1 ? ", " : "");
        strcat(str, current_range);
    }
}

void net_cleanup()
{
    if (!g_conns)
        return;
    free_task_list(g_conns);
    free_port_ranges();
}

