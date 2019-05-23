#include <pthread.h>
#include <stdio.h>

#include "threads.h"
#include "net.h"
#include "colors.h"
#include "common.h"

static host_t** g_host_list;
static int g_socket_timeout;
static int g_color = 1;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* thread_run(void* data)
{
	tdata_t* d = (tdata_t*) data;
	size_t current;
	uint16_t port;

	for (current = d->start; current <= d->stop; ++current)
	{
		host_t* h = g_host_list[current];
		LOCK(&g_mutex);
		info("%s%s%s (%s%s%s):\n",
				COLOR_IF(CYAN), h->hostname, COLOR_IF(RESET),
				COLOR_IF(MAGENTA), h->ip, COLOR_IF(RESET));
		UNLOCK(&g_mutex);
		// Loop through ports
		for (port = d->port_start; port <= d->port_stop; ++port)
		{
			if (connect_to_host(h->ip, port, g_socket_timeout) != 0)
			{
				LOCK(&g_mutex);
				dbg("  %5d: closed\n", port);
				UNLOCK(&g_mutex);
			}
			else
			{
				LOCK(&g_mutex);
				info("  %s%5d: open%s\n",
						COLOR_IF(GREEN), port, COLOR_IF(RESET));
				UNLOCK(&g_mutex);
			}
		}
	}
	
	return NULL;
}

static void set_thread_data(tdata_t* data, int id, size_t start, size_t stop, uint16_t port_start, uint16_t port_stop)
{
	data->id = id;
	data->start = start;
	data->stop = stop;
	data->port_start = port_start;
	data->port_stop = port_stop;
	printf("Thread ID #%d, IDX_start: %d, IDX_end: %d, Port start: %d, Port end: %d\n",
		id, start, stop, port_start, port_stop);
}

void process_hosts(host_t** host_list, size_t count,
					size_t nthreads,
					uint16_t port_start, uint16_t port_stop,
					int socket_timeout)
{
	size_t i, start, stop, items_per_thread;
	pthread_t thread[nthreads];
	pthread_attr_t attr;
	
	g_host_list = host_list;
	g_socket_timeout = socket_timeout;
	
	tdata_t arg[nthreads];
	pthread_attr_init(&attr);
	
	// Number of "connections" to be done
	items_per_thread = count * (port_stop - port_start + 1) / nthreads;
	
	dbg("I will use %d thread%s for parallel processing, %zu hosts/thread\n",
		nthreads, nthreads > 1 ? "s" : "",
		items_per_thread);
		
	return;
			
	for (i = 0; i < nthreads; ++i)
	{
		start = i * items_per_thread;
		stop = (i < nthreads - 1) ?
			(i + 1) * items_per_thread - 1 :
			 count - 1;
		set_thread_data(&arg[i], i, start, stop, port_start, port_stop);
		pthread_create(&thread[i], &attr, thread_run,  (void*)&arg[i]);
    }
    for (i = 0; i < nthreads; i++)
    {
        pthread_join(thread[i], NULL);
	}
}