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
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "common.h"

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
    // Set this socket NON BLOCKING
//     fcntl(sockfd, F_SETFL, O_NONBLOCK);

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
//TODO: return err/suceess, return list as arg
host_t** build_hosts_list(char* str)
{
    host_t** out;
    char ip[16];
    if (is_ip(str) == 0)
    {
        out = (host_t**) malloc (sizeof*out*2);
        out[0] = (host_t*) malloc(sizeof(host_t));
        strcpy(out[0]->hostname, str);
        strcpy(out[0]->ip, str);
        out[0]->dns_err = 0;
        out[1] = NULL;
    }
    else if (is_subnet(str) == 0)
    {
        size_t count = 0;
        uint32_t i;
        char ip_start[16];
        char ip_current[16];
        if (compute_ip_range(str, ip_start, &count) != 0)
        {
            out = (host_t**) malloc(sizeof*out);
            out[0] = NULL;
            return out;
        }
        // Allocate a big array of 'count' ip addresses in the pool
        out = (host_t**) malloc (sizeof*out * count);
        uint32_t ip_start_bits = ipaddr_2_bits(ip_start);
        for (i = 0; i < count; ++i)
        {
            out[i] = (host_t*) malloc(sizeof(host_t));
            out[i]->dns_err = 0;
            // Translate this numeric repr into a readable IP address
            bits_2_ipaddr(ip_start_bits + i, ip_current);
            // Store this IP address in the corresponding struct
            strcpy(out[i]->hostname, ip_current);
            strcpy(out[i]->ip, ip_current);
        }
    }
    else
    {
        out = (host_t**) malloc (sizeof*out*2);
        // Do DNS lookup
        if (do_dns_lookup(str, ip) != 0) 
        {
            out[0] = out[1] = NULL;
            return out;
        }
        out[0] = (host_t*) malloc(sizeof(host_t));
        strcpy(out[0]->hostname, str);
        strcpy(out[0]->ip, ip);
        out[0]->dns_err = 0;
        out[1] = NULL;
    }
    return out;
}

void free_host_list(host_t** host_list)
{
    host_t* current_host;
    host_t** arr = host_list;
    if (!host_list)
        return;

    for (current_host = *arr; current_host; current_host=*++arr)
        free(current_host);

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
