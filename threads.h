#ifndef PHSCAN_THREADS_H_
#define PHSCAN_THREADS_H_

#define PHSCAN_CS_PROTECT(STATEMENT, MUTEX_OBJ) \
    pthread_mutex_lock(MUTEX_OBJ);\
    STATEMENT;\
    pthread_mutex_unlock(MUTEX_OBJ);


#include <stdio.h>

#include "net/net.h"

struct thread_data
{
    int id;
    size_t idx_start;
    size_t idx_stop;
    int (*conn_hdlr)(const char*, port_t);
};

void* thread_run(void* data);

#endif /* PHSCAN_THREADS_H_ */
