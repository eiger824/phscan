#include <stdio.h>

#include "common.h"


void err(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
}

void die(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    err(msg, args);
    va_end(args);
}
