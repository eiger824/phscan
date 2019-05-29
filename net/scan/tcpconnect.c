#define _DEFAULT_SOURCE

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcpconnect.h"

int connect_to_host(char* host, uint16_t port, int msecs)
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
    servaddr.sin_addr.s_addr = inet_addr(host);
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
        tv.tv_sec = msecs / 1e3;
        tv.tv_usec = msecs * 1e3;

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

