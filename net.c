#define _DEFAULT_SOURCE

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <regex.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "common.h"
#include "colors.h"

static int g_color = 1;

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

int connect_to_host(char* host, uint16_t port, int msecs)
{
    struct sockaddr_in servaddr;
    int sockfd;
    int res;
    fd_set wfd,rfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
    {
        return 1;
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
            err("Unexpected error: %d (%s)\n", errno, strerror(errno));
            close(sockfd);
            return 1;
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
            return 2;
        }
        else if (res == 1)
        {
            // SUCCESS
            close(sockfd);
            return 0;
        }
        else
        {
            // Connect timed out => error happened
            close(sockfd);
            return 3;
        }
    }
    close(sockfd);
    return 0;
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

static host_t** alloc_n_hosts(size_t count)
{
	host_t** out;
	
	out = (host_t**) malloc (sizeof *out * count);
	
	return out;
}

static void add_new_host(host_t** list, size_t index, host_t* host, uint16_t port_start, uint16_t port_stop)
{
    uint16_t i;
	if (!list)
		return;
	list[index] = (host_t*) malloc (sizeof(host_t));
	strcpy(list[index]->ip, host->ip);
	strcpy(list[index]->hostname, host->hostname);
	list[index]->dns_err = host->dns_err;
    list[index]->pinfo =
        (struct port_info*) malloc(sizeof(struct port_info) * (port_stop - port_start + 1));
    for (i = port_start; i < port_stop; ++i)
    {
        list[index]->pinfo[i - port_start].portno = i;
    }
}

host_t** build_host_list(int argc, char** argv, int opt_index, size_t* n,
        uint16_t port_start, uint16_t port_stop)
{
	host_t** hosts;
	int i;
	size_t current = 0;
	
	if (!argv)
		return NULL;
	
	*n = get_total_host_count(argc, argv, optind);
	
    hosts = alloc_n_hosts(*n + 1);
	hosts[*n] = NULL;
	
	host_t h;
	for (i = opt_index; i < argc; ++i)
	{
		if ( is_ip(argv[i]) == 0)
		{
			strcpy(h.ip, argv[i]);
            strcpy(h.hostname, argv[i]);
			h.dns_err = 0;
			add_new_host(hosts, current++, &h, port_start, port_stop);
		}
        else if ( is_subnet(argv[i]) == 0)
        {
			size_t k;
			char ip_start[16];
			char ip_current[16];
            compute_ip_range(argv[i], ip_start, &k);
			uint32_t ip_start_bits = ipaddr_2_bits(ip_start);
            for (size_t i = 0; i < k; ++i)
			{
				h.dns_err = 0;
				// Translate this numeric repr into a readable IP address
				bits_2_ipaddr(ip_start_bits + i, ip_current);
				// Store this IP address in the corresponding struct
				strcpy(h.hostname, ip_current);
				strcpy(h.ip, ip_current);
				// Add this host to the global list
                add_new_host(hosts, current++, &h, port_start, port_stop);
			}
        }
        else
		{
			char ip[16];
			
			h.dns_err = do_dns_lookup(argv[i], ip);
				
			strcpy(h.ip, ip);
			strcpy(h.hostname, argv[i]);
			
            add_new_host(hosts, current++, &h, port_start, port_stop);
		}
	}
	
	return hosts;
}

void free_host_list(host_t** host_list)
{
    host_t* current_host;
    host_t** arr = host_list;
    if (!host_list)
        return;

    for (current_host = *arr; current_host; current_host=*++arr)
    {
        free(current_host->pinfo);
        free(current_host);
    }

    free(host_list);
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

void dump_host_info(host_t** host_list, uint16_t port_start, uint16_t port_end)
{
    host_t** arr = host_list;
    host_t* h;

    for (h = *arr; h; h = *++arr)
    {
        info("%s%s%s (%s%s%s):\n",
                COLOR_IF(CYAN), h->hostname, COLOR_IF(RESET),
                COLOR_IF(MAGENTA), h->ip, COLOR_IF(RESET));

        for (uint16_t p = port_start; p <= port_end; ++p)
        {
            if (h->pinfo[p - port_start].status == PHSCAN_PORT_CLOSED)
                dbg("  %5d: closed\n", p);
            else
                info("  %s%5d: open%s\n",
                        COLOR_IF(GREEN), p, COLOR_IF(RESET));
        }

    }
}
