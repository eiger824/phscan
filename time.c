#include <stdio.h>
#include <sys/time.h>

#include "time.h"

void set_timer(struct timeval *t0)
{
    gettimeofday(t0, NULL);
}

double get_elapsed_secs(struct timeval t0)
{
    struct timeval t1;
    gettimeofday(&t1, NULL);
    return (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_usec - t0.tv_usec) / 1e6;
}

