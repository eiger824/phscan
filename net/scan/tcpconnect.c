#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif  /* _DEFAULT_SOURCE */

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcpconnect.h"
#include "common.h"
#include "threads.h"
#include "progress.h"

static int g_msecs;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static struct connection* g_conns;
static size_t g_conn_count = 0;
static size_t g_task_progress = 0;

void* tcpconn_thread_run (void* arg)
{
    struct thread_data* d = (struct thread_data*)arg;
    struct connection* c;
    size_t i;
    int v = get_verbose();

    PHSCAN_CS_PROTECT(dbg("Thread[%d]. Processing tasks [%zu - %zu]\n", d->id, d->idx_start, d->idx_stop), &m);

    for (i = d->idx_start; i <= d->idx_stop; ++i)
    {
        // Get the current host
        c = &g_conns[i];
        if (d->conn_hdlr(c->ip, c->pinfo.portno) != PHSCAN_PORT_OPEN)
            c->pinfo.status = PHSCAN_PORT_CLOSED;
        else
            c->pinfo.status = PHSCAN_PORT_OPEN;

        // For the progress bar
        if (v)
        {
            PHSCAN_CS_PROTECT(notify_progress(++g_task_progress, g_conn_count), &m);
        }
    }

    return NULL;
}

int tcpconnect_run_tasks(struct connection* conns, size_t nr_tasks, int nr_threads)
{
    size_t tasks_per_thread;
    int i;
    pthread_t threads[nr_threads];
    struct thread_data tdata[nr_threads];
    pthread_attr_t attrs;

    if (!conns || nr_tasks == 0)
        return PHSCAN_ERROR;

    // set the global connections to make
    g_conns = conns;
    g_conn_count = nr_tasks;

    // Init thread attributes
    pthread_attr_init(&attrs);

    // For the animation
    set_bar_length();
    set_bar_header("Progress: ");

    tasks_per_thread = nr_tasks / nr_threads;
    // Let's make this worth: each thread must have at least
    // 10 tasks
    if (tasks_per_thread < 10)
    {
        dbg("Nr. tasks is too low, running with 1 thread\n");
        nr_threads = 1;
    }

    for (i = 0; i < nr_threads; ++i)
    {
        struct thread_data* d = &tdata[i];
        d->id = i;
        d->conn_hdlr = connect_to_host;
        d->idx_start = i * tasks_per_thread;
        d->idx_stop = i < nr_threads - 1 ?
            (i + 1) * tasks_per_thread - 1 :
            nr_tasks - 1;

        if (pthread_create(&threads[i], &attrs,
                    tcpconn_thread_run, (void*) d) != PHSCAN_SUCCESS)
        {
            perror("pthread_create() failed");
            return PHSCAN_ERROR;
        }
    }

    for (i = 0; i < nr_threads; ++i)
        pthread_join(threads[i], NULL);

    return PHSCAN_SUCCESS;
}

int connect_to_host(const char* ip, port_t port)
{
    struct sockaddr_in servaddr;
    int sockfd;
    int res;
    fd_set wfd,rfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
    {
        return 2;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(port);

    // Attempt connection to socket
    res = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (res == -1)
    {
        // Check errno, should be EINPROGRESS
        if (errno != EINPROGRESS)
        {
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }

        FD_ZERO(&wfd);
        FD_SET(sockfd, &wfd);
        FD_ZERO(&rfd);
        FD_SET(sockfd, &rfd);

        // Set out desired timeout
        struct timeval tv;
        tv.tv_sec = g_msecs / 1e3;
        tv.tv_usec = g_msecs * 1e3;

        res = select(sockfd +1, &rfd, &wfd, NULL, &tv);
        if (res == -1)
        {
            // ERROR ocurred => unsuccessful
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
        else if (res == 1)
        {
            // SUCCESS
            close(sockfd);
            return PHSCAN_PORT_OPEN;
        }
        else
        {
            // Connect timed out => error happened
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
    }
    close(sockfd);
    return PHSCAN_PORT_OPEN;
}

void set_socket_timeout(int ms)
{
    g_msecs = ms;
}

int get_socket_timeout()
{
    return g_msecs;
}
