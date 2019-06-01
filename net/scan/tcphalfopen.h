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

struct sniffer_thread_data
{
    int id;
    struct connection* conns;
    size_t nconns;
};


int process_packet(uint8_t* buffer, int size, char* ip, port_t* port);
unsigned short chksum(uint16_t* , int );
void set_ip_spoofing(int spoof);

// int half_open(const char* ip, port_t port);
int run_tasks(struct connection* conns, size_t n);

#endif /* NET_HALFOPEN_H_ */
