#ifndef OPTS_H_
#define OPTS_H_

#include <stdio.h>
#include <stdbool.h>

#include "net/net.h"

typedef struct options
{
    bool        ip_spoofing;
    int         socket_timeout; 
    size_t      thread_count;
    scan_type_t s;
    bool        ports_set;
    bool        verbose;
} options_t;

options_t*
options_create();

void
options_destroy(options_t* opt);

void
options_set_default(options_t* opt);

#endif /* OPTS_H_ */
