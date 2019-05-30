#ifndef NET_HALFOPEN_H_
#define NET_HALFOPEN_H_

#include <stdio.h>
#include "net.h"

void * receive_ack( void *ptr );
void process_packet(unsigned char* , int);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );

int half_open(const char* ip, port_t port);

#endif /* NET_HALFOPEN_H_ */
