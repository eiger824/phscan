#ifndef __NET_H_
#define __NET_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define         MAX_INT_VAL     0xffffffff

int sockfds[8];

char * bits_2_ipaddr(uint32_t ipaddr_bits, char *ip)
{
    uint8_t first = ipaddr_bits >> 24;
    uint8_t second = ipaddr_bits >> 16;
    uint8_t third = ipaddr_bits >> 8;
    uint8_t last = ipaddr_bits;
    sprintf(ip, "%d.%d.%d.%d", first, second, third, last);
    strcat(ip, "\0");
    return ip;
}

uint32_t ipaddr_2_bits(char *ipaddr_str)
{
    char *ipcpy = ipaddr_str;
    uint32_t ip = 0x00000000;
    char *c;
    char tmp[4];
    int cnt = 0;
    while ((c = strchr(ipaddr_str, '.')) != NULL)
    { 
        memcpy(tmp, ipaddr_str, c-ipaddr_str);
        tmp[c-ipaddr_str] = '\0';
        ip |= (atoi(tmp) << ((3 - cnt) * 8));
        ipaddr_str += (c - ipaddr_str) + 1;
        // Last check on last octet
        if ((c = strchr(ipaddr_str, '.')) == NULL)
        {
            memcpy(tmp,ipaddr_str,strlen(ipaddr_str));
            tmp[strlen(ipaddr_str)] = '\0';
            ip |= atoi(tmp);
            break;
        }
        cnt++;
    }
    ipaddr_str = ipcpy;
    return ip;
}

char *get_next_ipaddr(char *current, char *next)
{
    uint32_t c = ipaddr_2_bits(current);
    next = bits_2_ipaddr(++c, next);
    return next;
}

#endif   /* __NET_H */
