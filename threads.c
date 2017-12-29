#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include "time.h"
#include "threads.h"

#define     h_addr      h_addr_list[0] /* for backward compatibility */

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int err;
static struct hostent *host;
static int sockfd;

pthread_t working_threads[MAX_THREAD_COUNT];
unsigned  current_running_threads = 0;
retval_t retvals[MAX_THREAD_COUNT];

void *sock_connect(void *data)
{
    // Parse incoming data to current working thread
    pthread_mutex_lock(&mutex);
    thread_data_t *d = (thread_data_t*)data;
    pthread_mutex_unlock(&mutex);

    if (isdigit(d->ip[0]))
    {
        pthread_mutex_lock(&mutex);
        d->sa->sin_addr.s_addr = inet_addr(d->ip);
        pthread_mutex_unlock(&mutex);
    }
    else if ( (host = gethostbyname(d->ip)) != 0)
    {
        pthread_mutex_lock(&mutex);
        strncpy((char*)&d->sa->sin_addr , (char*)host->h_addr , sizeof d->sa->sin_addr);
        pthread_mutex_unlock(&mutex);
    }
    else
    {
        pthread_mutex_lock(&mutex);
        strerror(errno);
        err = 1;
        retvals[d->id].code = err;
        retvals[d->id].ip = d->ip;
        pthread_mutex_unlock(&mutex);
    }

    //Fill in the port number
    pthread_mutex_lock(&mutex);
    d->sa->sin_port = htons(d->port);
    pthread_mutex_unlock(&mutex);
    //Create a socket of type internet
    pthread_mutex_lock(&mutex);
    sockfd = socket(AF_INET , SOCK_STREAM , 0);
    pthread_mutex_unlock(&mutex);

    //Check whether socket created fine or not
    if (sockfd < 0) 
    {
        pthread_mutex_lock(&mutex);
        err = 1;
        retvals[d->id].code = err;
        retvals[d->id].ip = d->ip;
        pthread_mutex_unlock(&mutex);

    }
    pthread_mutex_lock(&mutex);
    err = connect(sockfd, (struct sockaddr*)&d->sa, sizeof d->sa);
    pthread_mutex_unlock(&mutex);

    retvals[d->id].code = err;
    retvals[d->id].ip = d->ip;
    if (sockfd >= 0)
    {
        pthread_mutex_lock(&mutex);
        close(sockfd);
        pthread_mutex_unlock(&mutex);
    }
    // Close this socket
    pthread_exit(&retvals[d->id]);
    return NULL;
}

void fill_thread_data(thread_data_t *data, int id, int port,
        struct sockaddr_in *sa, char *ip)
{
    data->id = id;
    data->port = port;
    data->sa = sa;
    data->ip = ip;
}

