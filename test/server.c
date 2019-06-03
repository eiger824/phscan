#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "common.h"
#include "threads.h"

#define SA struct sockaddr

static int* g_sockfds = NULL;
static port_t* g_port_list = NULL;
static size_t g_port_count;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_t* g_threads;
static struct thread_info_data* g_tdata;

struct thread_info_data
{
    int id;
    port_t portno;
    size_t index;
    int socket_type;
};

static void add_new_port(port_t port)
{
    if (g_port_list == NULL)
    {
        g_port_list = (port_t* ) malloc (sizeof(port_t) * USHRT_MAX);
    }
    g_port_list[g_port_count++] = port;
}

void server_cleanup()
{
    if (g_port_list)
    {
        free(g_port_list);
        g_port_list = NULL;
    }
    if (g_sockfds)
    {
        free(g_sockfds);
        g_sockfds = NULL;
    }
    if (g_threads)
    {
        free(g_threads);
        g_threads = NULL;
    }
    if (g_tdata)
    {
        free(g_tdata);
        g_tdata = NULL;
    }
}

static void usage(char* program)
{
    printf(
            "USAGE: %s [ARGS] PORT1[[:,-]PORT2]\n"
            "ARGS:\n"
            " -d         Print some debug info\n"
            " -h         Print this help and exit\n"
            " -p <proto> L4 protocol to be used: tcp,udp (defaults to tcp)\n"
            , basename(program)
          );
}

static void sighdlr(int signo)
{
    switch (signo)
    {
        case SIGINT:
            printf("\nSIGINT caught, terminating server\n");
            server_cleanup();
            exit(SIGINT);
        default:
            server_cleanup();
            exit(PHSCAN_ERROR);
    }
}

static int compute_ports(int argc, char** argv, int optidx)
{
    int i;
    port_t p;
    port_t pstart, pstop;

    // parse the positional arguments
    if (argc - optind == 0)
    {
        err("No ports were provided\n");
        usage(argv[0]);
        return PHSCAN_ERROR;
    }
    for (i = optidx; i < argc; ++i)
    {
        if (parse_ports(argv[i], &pstart, &pstop) != PHSCAN_SUCCESS)
        {
            err("Error parsing ports\n");
            return PHSCAN_ERROR;
        }
        for (p = pstart; p <= pstop; ++p)
            add_new_port(p);
    }
    return PHSCAN_SUCCESS;
}

static void* start_parallel_server(void* data)
{
    port_t portno;
    int connfd, socket_type;
    socklen_t s;
    struct sockaddr_in servaddr, cli; 
    struct thread_info_data* d = (struct thread_info_data*) data;

    portno = d->portno;
    socket_type = d->socket_type;

    // socket create and verification
    if ((g_sockfds[d->index] = socket(AF_INET, socket_type, 0)) == -1)
    {
        perror("socket");
        exit (1);
    }
    PHSCAN_CS_PROTECT(dbg("Socket successfully created.\n"), &m);

    memset(&servaddr, 0, sizeof(servaddr));

    // Assign IP and port
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(portno);

    // Binding newly created socket to given IP and verification
    if ((bind(g_sockfds[d->index], (SA*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("bind");
        exit (1);
    }
    PHSCAN_CS_PROTECT(dbg("Socket successfully binded.\n"), &m);

    // Now server is ready to listen and verification
    if ((listen(g_sockfds[d->index], 5)) != 0)
    {
        perror("listen");
        exit (1);
    }
    PHSCAN_CS_PROTECT(info("[Thread %p] Server listening to 0.0.0.0/0 on port %d ...\n", (void*)pthread_self(), portno), &m);

    while (1)
    {
        // Accept the data packet from client and verification
        connfd = accept(g_sockfds[d->index], (SA*)&cli, &s);
        if (connfd < 0)
        {
            perror("accept");
            exit (1);
        }
        PHSCAN_CS_PROTECT(info("[Thread %p] Client `%s' connected.\n", (void*)pthread_self(), inet_ntoa(cli.sin_addr)), &m);
    }

    server_cleanup();
    return NULL;
}

// Driver function
int main(int argc, char* argv[])
{
    int ret;
    int c, socket_type;
    char proto[16];
    size_t i;
    pthread_attr_t attrs;

    if (signal(SIGINT, sighdlr) != 0)
    {
        fprintf(stderr, "Error registering SIGINT\n");
        return 1;
    }

    strcpy(proto, "tcp");
    socket_type = SOCK_STREAM;
    // Parse options
    while ((c = getopt(argc, argv, "dhl:p:")) != EOF)
    {
        switch (c)
        {
            case 'd':
                info("Verbose is ON\n");
                set_verbose(1);
                break;
            case 'h':
                usage(argv[0]);
                exit (0);
            case 'p':
                // check proto
                if (strcmp(optarg, "tcp") != 0 && strcmp(optarg, "udp"))
                {
                    fprintf(stderr, "Unknown protocol \"%s\"\n", optarg);
                    usage(argv[0]);
                    exit (1);
                }
                strcpy(proto, optarg);
                if (!strcmp(proto, "tcp")) socket_type = SOCK_STREAM;
                else socket_type = SOCK_DGRAM;
                break;
            default:
                usage(argv[0]);
                exit (1);
        }
    }
    dbg("Chosen L4-protocol: %s\n", proto);

    if (compute_ports(argc, argv, optind) != PHSCAN_SUCCESS)
    {
        return PHSCAN_ERROR;
    }

    // Init the socket fd array
    g_sockfds = (int*) malloc(sizeof(int) * g_port_count);
    memset(g_sockfds, 0, sizeof(int) * g_port_count);

    // Init the thread array
    g_threads = (pthread_t*) malloc (sizeof(pthread_t) * g_port_count);
    g_tdata = (struct thread_info_data*) malloc (sizeof(struct thread_info_data) * g_port_count);

    pthread_attr_init(&attrs);

    // Create a thread per listening port (don't overuse..)
    for (i = 0; i < g_port_count; ++i)
    {
        g_tdata[i].id = i;
        g_tdata[i].portno = g_port_list[i];
        g_tdata[i].index = i;
        g_tdata[i].socket_type = socket_type;

        if ( (ret = pthread_create(&g_threads[i], &attrs, start_parallel_server, (void*)&g_tdata[i])) != PHSCAN_SUCCESS)
        {
            perror("pthread_create() failed");
            server_cleanup();
            return ret;
        }
    }

    for (i = 0; i < g_port_count; ++i)
        pthread_join(g_threads[i], NULL);

    return PHSCAN_SUCCESS;
}

