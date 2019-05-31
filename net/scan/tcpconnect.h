#ifndef NET_TCPCONNECT_H_
#define NET_TCPCONNECT_H_

#include <stdio.h>
#include <errno.h>

#include "net.h"

int connect_to_host(const char* ip, port_t port);
void set_socket_timeout(int ms);
int get_socket_timeout();

#endif /* NET_TCPCONNECT_H_ */
