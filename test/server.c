#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define MAX 80
#define SA struct sockaddr

int g_debug = 0;
int g_sockfd;

void usage(char* program)
{
    printf(
            "USAGE: %s [ARGS] <port>\n"
            "ARGS:\n"
            " -d         Print some debug info\n"
            " -h         Print this help and exit\n"
            " -p <proto> L4 protocol to be used: tcp,udp (defaults to tcp)\n"
            , basename(program)
          );
}

void sighdlr(int signo)
{
    switch (signo)
    {
        case SIGINT:
            printf("\nSIGINT caught, terminating server\n");
            close(g_sockfd);
            exit(SIGINT);
        default:
            exit(1);
    }
}

void info(const char* msg, ...)
{
    if (!g_debug) return;
    va_list args;
    va_start(args, msg);
    vprintf(msg, args);
    va_end(args);
}

// Driver function
int main(int argc, char* argv[])
{
    int connfd, len;
    struct sockaddr_in servaddr, cli;
    int c, portno;
    int socket_type;
    char proto[16];

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
                g_debug = 1;
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
    info("Chosen L4-protocol: %s\n", proto);
    // parse the positional arguments
    if (argc - optind != 1)
    {
        usage(argv[0]);
        exit (1);
    }
    portno = atoi(argv[optind]);

    // socket create and verification
    if ((g_sockfd = socket(AF_INET, socket_type, 0)) == -1)
    {
        perror("socket");
        exit (1);
    }
    info("Socket successfully created.\n");

    memset(&servaddr, 0, sizeof(servaddr));

    // Assign IP and port
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(portno);

    // Binding newly created socket to given IP and verification
    if ((bind(g_sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("bind");
        exit (1);
    }
    info("Socket successfully binded.\n");

    // Now server is ready to listen and verification
    if ((listen(g_sockfd, 5)) != 0)
    {
        perror("listen");
        exit (1);
    }
    info("Server listening to 0.0.0.0/0 on port %d ...\n", portno);

    while (1)
    {
        len = sizeof(cli);
        // Accept the data packet from client and verification
        connfd = accept(g_sockfd, (SA*)&cli, &len);
        if (connfd < 0)
        {
            perror("accept");
            exit (1);
        }
        info("Client `%s' connected.\n", inet_ntoa(cli.sin_addr));
    }
    return 0;
}

