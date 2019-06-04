#ifndef NET_ICMP_PING_H_
#define NET_ICMP_PING_H_

#include <stdio.h>
#include "net.h" 

#define     BUF_RECV_MAX    1024
#define     BUF_SEND_MAX    64

struct icmp_thread_data
{
    int id;
    size_t idx_start;
    size_t idx_stop;
};

struct icmp_listen_data
{
    int id;
    struct connection* conns;
    size_t nconns;
};

int icmp_run_tasks(struct connection* conns, size_t nr_tasks, int nr_threads);

#endif /* NET_ICMP_PING_H_ */
