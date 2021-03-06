#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common.h"

static int g_verbose = 0;
static int g_color = 0;

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
    vfprintf(stderr, msg, args);
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
    int ret, res;
    regex_t reg;

    res = 0;
    ret = regcomp(&reg, regex, REG_EXTENDED);
    if (ret)
    {
        err("Could not compile regex\n");
        return 1;
    }
    ret = regexec(&reg, str, 0, NULL, 0);
    if ( ret == REG_NOMATCH )
        res = 2;

    regfree(&reg);

    return res;
}

int parse_ports(const char* str, port_t* port_start, port_t* port_end)
{
    char delim;
    char* p;
    // Input will be in 'str'
    // Output should be a port start and end
    // In case a single port is provided => port_start = port_end

    if (regex_match(str, "^[0-9]+$") == 0)
    {
        // Simplest case, no ranges, single port
        *port_start = atoi(str);
        *port_end = *port_start; 
        if (verify_port(*port_start) || verify_port(*port_end))
            return PHSCAN_ERROR;
        return PHSCAN_SUCCESS;
    }

    if (regex_match(str, "^[0-9]+[[:blank:]]*([,-:][[:blank:]]*[0-9]+)?$") == 0)
    {
        delim = find_delim(str);
	if (delim != ',' && delim != '-' && delim != ':')
	    return PHSCAN_ERROR;

        *port_start = atoi(str);
        p = strchr(str, delim);
        *port_end = atoi(++p);
        if (verify_port(*port_start) || verify_port(*port_end))
            return PHSCAN_ERROR;
        return PHSCAN_SUCCESS;
    }

    return PHSCAN_ERROR;
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

int get_verbose()
{
    return g_verbose;
}

void set_color(int color)
{
    g_color = color;
}

int get_color()
{
    return g_color;
}

int get_random_integer(int min, int max)
{
    return rand() % ( max - min + 1) + min;
}

size_t get_win_size()
{
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    return ws.ws_col;
}
