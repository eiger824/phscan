#include <stdlib.h>

#include "opts.h"

options_t*
options_create()
{
    options_t* opt = (options_t*) malloc (sizeof *opt);

    return opt;
}

void
options_destroy(options_t* opt)
{
    free(opt);
}

void
options_set_default(options_t* opt)
{
    opt->ip_spoofing    = false;
    opt->ports_set      = false;
    opt->s              = PHSCAN_TCP_CONNECT;
    opt->socket_timeout = -1;
    opt->thread_count   = 1;
    opt->verbose        = false;
}
