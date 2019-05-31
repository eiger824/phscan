#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdarg.h>

#define         PHSCAN_PROGNAME      "phscan"
#define         PHSCAN_SIMPLE        0
#define         PHSCAN_SUCCESS       0
#define         PHSCAN_ERROR         1

#define         PHSCAN_VERSION       0.2

#define     port_t  uint16_t

void err(const char* msg, ...);
void info(const char* msg, ...);
void die(void (*usage_fun)(char*), char* program, const char* msg, ...);
void dbg(const char* msg, ...);
char *get_basename(char* str);
int regex_match(const char* str, const char* regex);
char find_delim(const char* str);
int verify_port(int port);
void set_verbose(int verbose);
int get_verbose();
void set_color(int color);
int get_color();
int get_random_integer(int min, int max);

#endif /* COMMON_H_ */
