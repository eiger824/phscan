#define _DEFAULT_SOURCE

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>
#include <regex.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "scan/tcpconnect.h"

#include "common.h"
#include "colors.h"

static int g_socket_timeout = 100; //ms
static struct port_range* g_port_ranges = NULL;
static size_t g_range_idx = 0;

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

/*
int connect_to_host(char* host, uint16_t port, int msecs)
{
    struct sockaddr_in servaddr;
    int sockfd;
    int res;
    fd_set wfd,rfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
    {
        return 2;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host);
    servaddr.sin_port = htons(port);

    // Attempt connection to socket
    res = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (res == -1)
    {
        // Check errno, should be EINPROGRESS
        if (errno != EINPROGRESS)
        {
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }

        FD_ZERO(&wfd);
        FD_SET(sockfd, &wfd);
        FD_ZERO(&rfd);
        FD_SET(sockfd, &rfd);

        // Set out desired timeout
        struct timeval tv;
        tv.tv_sec = msecs / 1e3;
        tv.tv_usec = msecs * 1e3;

        res = select(sockfd +1, &rfd, &wfd, NULL, &tv);
        if (res == -1)
        {
            // ERROR ocurred => unsuccessful
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
        else if (res == 1)
        {
            // SUCCESS
            close(sockfd);
            return PHSCAN_PORT_OPEN;
        }
        else
        {
            // Connect timed out => error happened
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
    }
    close(sockfd);
    return PHSCAN_PORT_OPEN;
}
*/

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

static void add_new_host(host_t* list, size_t index, host_t* h)
{
    if (!list)
        return;

    strcpy(list[index].hostname, h->hostname);
    strcpy(list[index].ip, h->ip);
    list[index].dns_err = h->dns_err;
    list[index].pinfo = h->pinfo;
    list[index].nports = h->nports;
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

static void fill_port_info(struct port_info* info)
{
    size_t i,j;
    struct port_range* r;
    size_t current = 0;
    if (!info)
        return;
    for (i = 0; i < g_range_idx; ++i)
    {
        r = &g_port_ranges[i];
        for (j = r->port_start; j<= r->port_stop; ++j)
        {
            info[current].portno = j;
            info[current].status = PHSCAN_PORT_CLOSED;
            current++;
        }
    }

}

host_t* build_hosts_list(int argc, char** argv, int opt_index, size_t* count)
{
    host_t* out;
    host_t new_host;
    size_t current = 0;
    char ip[16];
    char* str;
    size_t j, k, port_count;
    int i;

    *count = get_total_host_count(argc, argv, opt_index);
    port_count = get_total_port_count();

    out = (host_t*) malloc (sizeof *out * *count);
    new_host.dns_err = 0;
    // Allocate the port information structure
    dbg("Port_count = %zu, %zu hosts\n", port_count, *count);
    new_host.nports = port_count;

    for (i = opt_index; i < argc; ++i)
    {
        str = argv[i];
        if (is_ip(str) == 0)
        {
            strcpy(new_host.hostname, str);
            strcpy(new_host.ip, str);
            new_host.pinfo =
                (struct port_info*) malloc(sizeof(struct port_info) * port_count);
            fill_port_info(new_host.pinfo);
            add_new_host(out, current++, &new_host);
        }
        else if (is_subnet(str) == 0)
        {
            char ip_start[16];
            char ip_current[16];
            if (compute_ip_range(str, ip_start, &k) != 0)
            {
                return NULL;
            }
            // Allocate a big array of 'k' ip addresses in the pool
            uint32_t ip_start_bits = ipaddr_2_bits(ip_start);
            for (j = 0; j < k; ++j)
            {
                // Translate this numeric repr into a readable IP address
                bits_2_ipaddr(ip_start_bits + j, ip_current);
                // Store this IP address in the corresponding struct
                strcpy(new_host.hostname, ip_current);
                strcpy(new_host.ip, ip_current);
                new_host.pinfo =
                    (struct port_info*) malloc(sizeof(struct port_info) * port_count);
                fill_port_info(new_host.pinfo);
                add_new_host(out, current++, &new_host);
            }
        }
        else
        {
            // Do DNS lookup
            new_host.dns_err = do_dns_lookup(str, ip);
            if (new_host.dns_err != 0)
                strcpy(new_host.hostname, ip);
            else
                strcpy(new_host.hostname, str);

            strcpy(new_host.ip, ip);
            new_host.pinfo =
                (struct port_info*) malloc(sizeof(struct port_info) * port_count);
            fill_port_info(new_host.pinfo);
            add_new_host(out, current++, &new_host);
        }
    }
    return out;
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

void process_hosts(host_t* list, size_t n)
{
    port_t port;
    host_t* h;
    size_t i,j;
    size_t current;
    struct port_range* r;

    if (!list)
        return;
    for (i = 0; i < n; ++i)
    {
        // Get the current host
        h = &list[i];
	current = 0;
        // Go through all ranges
        for (j = 0; j < g_range_idx; ++j)
        {
            // Go through current range
            r = &g_port_ranges[j];
            for (port = r->port_start; port <= r->port_stop; ++port)
            {
                if (connect_to_host(h->ip, port, g_socket_timeout) != PHSCAN_PORT_OPEN)
                    h->pinfo[current].status = PHSCAN_PORT_CLOSED;
		else
                    h->pinfo[current].status = PHSCAN_PORT_OPEN;

		current++;
           }
        }
    }

}

void print_scan_results(host_t* hosts, size_t n)
{
    size_t i;
    port_t portidx, port;
    int status;
    host_t* h;
    if (!hosts)
        return;

    for (i = 0; i < n; ++i)
    {
        h = &hosts[i];
        info("%s%s%s (%s%s%s):\n",
                COLOR_IF(CYAN), h->hostname, COLOR_IF(RESET),
                COLOR_IF(MAGENTA), h->ip, COLOR_IF(RESET));

        for (portidx = 0; portidx < h->nports; ++portidx)
        {
            port = h->pinfo[portidx].portno;
            status = h->pinfo[portidx].status;
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

    if (!iface || !ip)
        return 1;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (strcmp(ifa->ifa_name, iface) != 0)
            continue;

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
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

void set_socket_timeout(int timeout)
{
    g_socket_timeout = timeout;
}

int get_socket_timeout()
{
    return g_socket_timeout;
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

void free_host_list(host_t* host_list, size_t n)
{
    size_t i;
    if (!host_list)
        return;

    for (i = 0; i < n; ++i)
        free(host_list[i].pinfo);

    free(host_list);
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
