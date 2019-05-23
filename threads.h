#ifndef THREADS_H_
#define THREADS_H_

#include <stdint.h>

#include "net.h"

typedef struct thread_data {
	int id;
	size_t start; // Start pos on host array
	size_t stop;  // End pos on host array
	size_t port_start;
	size_t port_stop;
} tdata_t;

void process_hosts(host_t* host_list, size_t count,
				size_t nthreads,
				uint16_t port_start, uint16_t port_stop,
				int socket_timeout);

#endif /* THREADS_H_ */
