#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "common.h"

static int g_verbose = 0;

void err(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
}

void info(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vprintf(msg, args);
    va_end(args);
}

void die(void (*usage_fun)(char*), char* program, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    err(msg, args);
    va_end(args);
    usage_fun(program);
    exit(1);
}

void dbg(const char* msg, ...)
{
    if (!g_verbose)
        return;

    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
}

char *get_basename(char* str)
{
    char *stripped = str;
    if (strchr(stripped, '/') == NULL) return stripped;
    while ((stripped = strchr(stripped, '/')) != NULL)
    {
        stripped++;
        if (strchr(stripped, '/') == NULL) break;
    }
    return stripped;
}

int regex_match(const char* str, const char* regex)
{
    int ret;
    regex_t reg;

    ret = regcomp(&reg, regex, REG_EXTENDED);
    if (ret)
    {
        err("Could not compile regex\n");
        return 1;
    }
    ret = regexec(&reg, str, 0, NULL, 0);
    if ( ret == REG_NOMATCH )
        return 2;
    return 0;
}

char find_delim(const char* str)
{
    unsigned int i;
    char c;
    for (i = 0; i < strlen(str); ++i)
    {
        c = str[i];
        if (!isdigit(c) && !isblank(c))
            return c;
    }
    // the string is verified to contain a non-numeric character,
    // so we never reach this point
    return '/';
}

int verify_port(int port)
{
    return !(port >= 0 && port <= USHRT_MAX);
}

void set_verbose(int verbose)
{
    g_verbose = verbose;
}

