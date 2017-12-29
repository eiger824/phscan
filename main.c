/*
   C port scanner
   */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>

#include "net.h"
#include "time.h"
#include "utils.h"
#include "threads.h"
#include "colors.h"

#define         PSCAN_SIMPLE        0
#define         PSCAN_ERROR         1
#define         PSCAN_RANGE         2

#define         VERSION             0.1

static char *hostname_start;
static char *hostname_end;

static struct timeval elapsed;
static retval_t lretvals[MAX_THREAD_COUNT];

typedef enum t_MODE
{
    m_NONE,
    m_IP,
    m_PORT,
    m_BOTH
} scan_mode_t;

void help(char *program)
{
    fprintf(stderr, "USAGE: %s [hv|V] m MODE p PORT(RANGE) H HOST(RANGE)\n",
            get_basename(program));
    fprintf(stderr, "-h\t\t  Show this help and exit\n");
    fprintf(stderr, "-H <host[/range]> Select hostname to scan\n");
    fprintf(stderr, "-m <mode>\t  Select mode: port, ip, both\n");
    fprintf(stderr, "\t\t  port : When selecting this mode, perform a portscan on the given host. -H must be set\n");
    fprintf(stderr, "\t\t  ip   : Perform a host scan on the given port. -p must be set\n");
    fprintf(stderr, "\t\t  both : When selecting this mode, perform both scans. Both -H and -p must be set\n");
    fprintf(stderr, "-p <port[:range]> Perform an IP address scanning on the specified port\n");
    fprintf(stderr, "-v\t\t  Show version information and exit\n");
    fprintf(stderr, "-V\t\t  Enable verbose\n");
    fprintf(stderr, "\nNote 1: The port range shall be applied using the following format: \"start:end\"\n");
    fprintf(stderr, "Note 2: The host range shall be applied using the standard network notation: \"SUBNET/MASK\"\n\n");
    fprintf(stderr, "Example usage 1: %s -m port -p 20:30 -H 192.168.1.1\t\tDo a port scan from 20 to 30 on the given host\n", get_basename(program));
    fprintf(stderr, "Example usage 2: %s -m ip   -p 80    -H 192.168.1.0/24\tDo a host scan in search for open port 80\n", get_basename(program));
    fprintf(stderr, "Example usage 3: %s -m both -p 10:20 -H 192.168.1.0/24\tPerform both port and host scans\n", get_basename(program));
}

void version(char *program)
{
    fprintf(stderr, "%s - version v%.2f, developed by eiger824\n",
            get_basename(program), VERSION);
}

int check_optarg_valid(const char* str, char delim)
{
    char *tmp;
    if ((tmp = strchr(str, delim)) != NULL) // Range char was provided
    {
        if (tmp == str || tmp == str + strlen(str) + 1)
        {
            return PSCAN_ERROR;
        }
        else
        {
            return PSCAN_RANGE;
        }
    }
    else
    {
        if (!strlen(str)) return PSCAN_ERROR;
        else return PSCAN_SIMPLE;
    }
}

int parse_ports(const char* str, int* port_start, int* port_end)
{
    int type;
    if ((type = check_optarg_valid(str, ':')) == PSCAN_ERROR) return PSCAN_ERROR;
    switch (type)
    {
        case PSCAN_RANGE:
            {
                char *end = strchr(str, ':');
                *port_end = atoi(end+1);
                char *start = (char*) malloc((sizeof *start) * 5);
                memcpy(start, str, end - str + 1);
                start[end-str] = '\0';
                *port_start = atoi(start);
                free(start);
                // Check port validity
                if (*port_start <= 0 || *port_start > USHRT_MAX)
                {
                    *port_start = 0;
                    *port_end = 0;
                    return PSCAN_ERROR;
                }
                break;
            }
        case PSCAN_SIMPLE:
            *port_start = atoi(str);
            // Set the port content to 0, not the pointer
            *port_end = 0;
            if (*port_start <= 0 || *port_start > USHRT_MAX)
            {
                *port_start = 0;
                *port_end = 0;
                return PSCAN_ERROR;
            }
            break;
    }
    // Last check: if any ptr is null, error
    return (!port_start || !port_end);
}

int parse_mode(const char* str, scan_mode_t *mode)
{
    if (!strcmp(str, "both"))
    {
        *mode = m_BOTH;
        return PSCAN_SIMPLE;
    }
    else if (!strcmp(str, "ip"))
    {
        *mode = m_IP;
        return PSCAN_SIMPLE;
    }
    else if (!strcmp(str, "port"))
    {
        *mode = m_PORT;
        return PSCAN_SIMPLE;
    }
    *mode = m_NONE;
    return PSCAN_ERROR;
}

int parse_hosts(const char *str)
{
    int type;
    if ((type = check_optarg_valid(str, '/')) == PSCAN_ERROR) return PSCAN_ERROR;

    // Allocate memory for the hostnames
    hostname_start = (char*) malloc ( (sizeof *hostname_start) * 100);
    hostname_end   = (char*) malloc ( (sizeof *hostname_end)   * 100);
    switch (type)
    {
        case PSCAN_RANGE:
            {
                char *end = strchr(str, '/');
                ++end;
                memcpy(hostname_end, end, strlen(end) + 1);
                hostname_end[strlen(end)] = '\0';

                char *start = (char*) malloc((sizeof *start) * 30);
                memcpy(start, str, end - str - 1);
                start[end-str] = '\0';
                strcpy(hostname_start, start);
                free(start);

                // Depending on what netmask, determine the start and end
                uint32_t netmask = MAX_INT_VAL;
                netmask = netmask << (sizeof(int) * 8 - atoi(hostname_end));
                uint32_t ipstart = ipaddr_2_bits(hostname_start);
                uint32_t wildcard = MAX_INT_VAL - netmask;
                uint32_t ipend = ipstart + wildcard;

                hostname_start = bits_2_ipaddr(ipstart, hostname_start);
                hostname_end = bits_2_ipaddr(ipend, hostname_end);
                return PSCAN_SIMPLE;
            }
        case PSCAN_SIMPLE:
            // No need for hostname end
            free (hostname_end);
            memcpy(hostname_start, str, strlen(str) + 1);
            hostname_start[strlen(str)] = '\0';
            // Copy local ptrs to global

            return PSCAN_SIMPLE;
    }
    return PSCAN_ERROR;
}


int main(int argc , char **argv)
{
    int err, c, i, sock;
    int port_start, port_end;
    int verbose = 0;

    struct sockaddr_in sa;
    scan_mode_t mode = m_NONE;
    char *program = argv[0];

    //Get the hostname to scan
    if (argc == 1)
    {
        fprintf(stderr, "Error: not enough input arguments\n");
        help(program);
        exit(2);
    }
    // Allocate memory for host start and end
    while ((c = getopt(argc, argv, "hH:m:p:vV")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(program);
                exit(0);
            case 'v':
                version(program);
                exit(0);
            case 'V':
                printf("Verbose is ON\n");
                verbose = 1;
                break;
            case 'H':
                if (parse_hosts(optarg) == PSCAN_ERROR)
                {
                    fprintf(stderr, "Wrong hostname format\n");
                    help(program);
                    exit(PSCAN_ERROR);
                }
                break;
            case 'm':

                if (parse_mode(optarg, &mode) == PSCAN_ERROR)
                {
                    fprintf(stderr, "Error: Unrecognized mode\n");
                    help(program);
                    exit(PSCAN_ERROR);
                }
                break;
            case 'p':
                if (parse_ports(optarg, &port_start, &port_end) == PSCAN_ERROR)
                {
                    fprintf(stderr, "Wrong port format\n");
                    help(program);
                    exit(PSCAN_ERROR);
                }
                break;
            default:
                help(program);
                exit(PSCAN_ERROR);
        }
    }
    // Check if hostname or port was set
    if (port_start == 0 || !hostname_start)
    {
        fprintf(stderr, "Error: at least one port or one start hostname must be given\n");
        help(program);
        exit(PSCAN_ERROR);
    }
    //Initialise the sockaddr_in structure
    strncpy((char*)&sa , "" , sizeof sa);
    sa.sin_family = AF_INET;
    // Action starts, depending on mode
    switch (mode)
    {
        case m_IP:
            printf("Hostname start: %s, Hostname end; %s\n", hostname_start, hostname_end);
            uint32_t current;
            char ip[100];
            set_timer(&elapsed);
            for (current = ipaddr_2_bits(hostname_start);
                    current < ipaddr_2_bits(hostname_end);
                    current+=MAX_THREAD_COUNT)
            {
                *ip = *bits_2_ipaddr(current, ip);
                //direct ip address, use it
                thread_data_t data[MAX_THREAD_COUNT];
                for (unsigned i=0; i<MAX_THREAD_COUNT; ++i) 
                {
                    if (verbose)
                        printf("Will scan: [%s]\n",ip);
                    fill_thread_data(&data[i], current_running_threads, port_start, &sa, ip); 
                    err = pthread_create(&working_threads[current_running_threads++],
                            NULL, &sock_connect, (void*)&data[i]);
                    // Fetch the next address
                    get_next_ipaddr(ip, ip);
                }
                // join the threads
                for (unsigned i=0; i<MAX_THREAD_COUNT; ++i)
                {
                    pthread_join(working_threads[i], (void**)&(lretvals[i]));
                }
                current_running_threads = 0;
                // Go through the results
                for (unsigned i=0; i<MAX_THREAD_COUNT; ++i)
                {
                    printf("%sHost: \"%s\", port %d is %s%s\n",
                            (!lretvals[i].code ? GREEN : ""),
                            retvals[i].ip, port_start, (!lretvals[i].code ? "open.":"closed."),
                            RESET);
                }
            }
            printf("Took %.2f seconds to scan\n", get_elapsed_secs(elapsed));
            exit(0);
            break;
        case m_BOTH:
            break;
        case m_PORT:
            //Start the port scan loop
            printf("Starting the portscan loop [%d-%d] on host \"%s\"\n"
                    , port_start, port_end, hostname_start);
            gettimeofday(&elapsed, NULL);
            for( i = port_start ; i <= port_end ; i++) 
            {
                //Fill in the port number
                sa.sin_port = htons(i);
                //Create a socket of type internet
                sock = socket(AF_INET , SOCK_STREAM , 0);

                //Check whether socket created fine or not
                if (sock < 0) 
                {
                    if (verbose)
                    {
                        printf(RED "Error connecting to port %d\n" RESET, i);
                    }
                }
                else
                {
                    //Connect using that socket and sockaddr structure
                    err = connect(sock , (struct sockaddr*)&sa , sizeof sa);

                    //not connected
                    if( err < 0 )
                    {
                        if (verbose)
                        {
                            printf("%-5d closed\n" , i);
                            fflush(stdout);
                        }
                    }
                    //connected
                    else
                    {
                        printf(GREEN "%-5d open\n" RESET,  i);
                    }
                    close(sock);
                }
            }
            break;
        case m_NONE:
            fprintf(stderr, "Error: mode must be set\n");
            help(program);
            exit(PSCAN_ERROR);
        default:
            fprintf(stderr, "Unknown mode %d\n", mode);
            help(program);
            exit(PSCAN_ERROR);
    }
    printf("Done (elapsed time: %.2f s).\n", get_elapsed_secs(elapsed));
    free(hostname_start);
    return(0);
} 
