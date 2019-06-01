#ifndef NET_HALFOPEN_H_
#define NET_HALFOPEN_H_

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif  /* _DEFAULT_SOURCE */

#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "net.h"

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

int process_packet(uint8_t* , int);
unsigned short csum(unsigned short * , int );
void set_ip_spoofing(int spoof);

int half_open(const char* ip, port_t port);

#endif /* NET_HALFOPEN_H_ */
