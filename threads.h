#ifndef __THREADS_H_
#define __THREADS_H_

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

#include "time.h"

#define     MAX_THREAD_COUNT        1

typedef struct return_val_struct
{
    int code;
    char *ip;
} retval_t;

typedef struct thread_data
{
    int id;
    int port;
    struct sockaddr_in *sa;
    char *ip;
} thread_data_t;


/*
 * Function:	sock_connect
 * Brief:	    Function pointer, thread start point
 * @param data:	Pointer to raw data containing some data individual to every
                thread 
 * Returns:	    The return values will be passed on to the calling thread via
                the pthread_interface 
*/
void *sock_connect(void *data);

/*
 * Function:	fill_thread_data
 * Brief:	    Given an input thread_data_t structure, this function fills it
                with the provided values 
 * @param data:	Thread data structure to fill
 * @param id:	Thread ID to use
 * @param port:	Port to attempt the connection to
 * @param sa:	Server sockaddr_in structure, containing information about the
                server to connect to 
 * @param ip:	IPv4 address to connect to
 * Returns:	    Nothing
*/
void fill_thread_data(thread_data_t *data, int id, int port,
        struct sockaddr_in *sa, char *ip);

#endif  /* __THREADS_H_ */
