#define _DEFAULT_SOURCE

#include <stdint.h>
#include <string.h>
#include <unistd.h>
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

int connect_to_host(char* host, uint16_t port)
{
    struct sockaddr_in servaddr;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return 1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host);
    servaddr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
    {
        close(sockfd);
        return 1;
    }
    // Close & exit, worked
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
        out = (host_t**) malloc (sizeof*out * 123123);

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
