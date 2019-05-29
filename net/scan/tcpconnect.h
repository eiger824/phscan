#ifndef NET_TCPCONNECT_H_
#define NET_TCPCONNECT_H_

#include <stdio.h>
#include <errno.h>

#include "net/net.h"

int connect_to_host(char* host, uint16_t port, int msecs);

#endif /* NET_TCPCONNECT_H_ */
