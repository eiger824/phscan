#define _DEFAULT_SOURCE

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcpconnect.h"

static int g_msecs;

int connect_to_host(const char* ip, port_t port)
{
    struct sockaddr_in servaddr;
    int sockfd;
    int res;
    fd_set wfd,rfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
    {
        return 2;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(port);

    // Attempt connection to socket
    res = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (res == -1)
    {
        // Check errno, should be EINPROGRESS
        if (errno != EINPROGRESS)
        {
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }

        FD_ZERO(&wfd);
        FD_SET(sockfd, &wfd);
        FD_ZERO(&rfd);
        FD_SET(sockfd, &rfd);

        // Set out desired timeout
        struct timeval tv;
        tv.tv_sec = g_msecs / 1e3;
        tv.tv_usec = g_msecs * 1e3;

        res = select(sockfd +1, &rfd, &wfd, NULL, &tv);
        if (res == -1)
        {
            // ERROR ocurred => unsuccessful
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
        else if (res == 1)
        {
            // SUCCESS
            close(sockfd);
            return PHSCAN_PORT_OPEN;
        }
        else
        {
            // Connect timed out => error happened
            close(sockfd);
            return PHSCAN_PORT_CLOSED;
        }
    }
    close(sockfd);
    return PHSCAN_PORT_OPEN;
}

void set_socket_timeout(int ms)
{
    g_msecs = ms;
}

int get_socket_timeout()
{
    return g_msecs;
}
