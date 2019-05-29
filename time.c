#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "time.h"

void set_timer(struct timeval *t0)
{
    gettimeofday(t0, NULL);
}

void stop_timer(struct timeval* t0, char* units)
{
    struct timeval t1;
    gettimeofday(&t1, NULL);
    long secs = t1.tv_sec - t0->tv_sec;
    long usecs =  t1.tv_usec - t0->tv_usec;
    if (secs == 0)
    {
        if (usecs / 1e3 == 0)
        {
            sprintf(units, "%ld us", usecs);
        }
        else
        {
            sprintf(units, "%.2f ms", (double) (usecs) / 1e3);
        }
    }
    else
    {
        if (secs > 3599)
        {
            int hours = secs / 3600;
            int seconds = secs % 3600;
            int minutes = seconds / 60;
            seconds = seconds % 60;

            sprintf(units, "%dh%dm%d", hours, minutes, seconds);
        }
        else if (secs > 59)
        {
            int minutes = secs / 60;
            int seconds = secs % 60;
            sprintf(units, "%dm%ds", minutes, seconds);
        }
        else
        {
            sprintf(units, "%.2f s", (double)secs + (double)usecs/1e6);
        }
    }
}

