#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif  /* _DEFAULT_SOURCE */

#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <limits.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcphalfopen.h" 
#include "net.h"
#include "common.h"

struct in_addr g_dest_ip;
static int g_spoofing = 0;

static void get_random_ip(char* ip, size_t n)
{
    int a, b, c, d;
    srand(time(NULL));
    if (!ip)
        return;

    memset(ip, 0, n);

    a = get_random_integer(1, 253);
    b = get_random_integer(1, 253);
    c = get_random_integer(1, 253);
    d = get_random_integer(1, 253);

    sprintf(ip, "%d.%d.%d.%d", a, b, c, d);
}

int half_open(const char* ip, port_t port)
{
    int s;
    socklen_t sl;
    ssize_t data_size;
    //Datagram to represent the packet
    char datagram[4096];	
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;

    struct sockaddr_in  dest;
    struct sockaddr saddr;

    char source_ip[16];

    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    //Create a raw socket
    if ( (s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP)) < 0)
    {
        perror("socket() failed");
        return PHSCAN_PORT_CLOSED;
    } 

    g_dest_ip.s_addr = inet_addr( ip );

    if (g_spoofing)
        // Get a random IP
        get_random_ip(source_ip, sizeof(source_ip));
    else
        // Get our local IP
        get_local_ip( NULL, source_ip );

    memset (datagram, 0, sizeof(datagram));	/* zero out the buffer */

    /*
     * IP Header
     */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons ( get_random_integer(100, USHRT_MAX) );	//Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
    iph->daddr = g_dest_ip.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    /*
     * TCP Header
     */
    tcph->source = htons ( get_random_integer(1040, 60000) );
    tcph->dest = htons (port);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons ( 14600 );	// maximum allowed window size
    tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("setsockopt() failed");
        return 1;
    }

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = g_dest_ip.s_addr;

    tcph->dest = htons ( port );
    tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons( sizeof(struct tcphdr) );

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    //Send the packet
    if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
    {
        perror("sendto() failed");
        return 1;
    }

    int ret;
    // Receive from buffer, await until done
    while (1)
    {
        if ( (data_size = recvfrom(s , buffer , 65536 , 0 , &saddr , &sl)) < 0 )
        {
            perror("recvfrom() error");
            fflush(stdout);
            return 1;
        }

        ret = process_packet(buffer , data_size);
        //Now process the packet
        if ( ret == PHSCAN_PORT_OPEN || ret == PHSCAN_PORT_CLOSED)
            break;
    }
    return ret;
}

/*
   Method to sniff incoming packets and look for Ack replies
   */
int process_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
    if (size < 0 || !buffer)
        return PHSCAN_PKT_UNRELATED;

    if (iph->protocol == 6)
    {
        struct iphdr *iph = (struct iphdr *)buffer;
        iphdrlen = iph->ihl*4;

        struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        if (tcph->syn == 1 && tcph->ack == 1
                && source.sin_addr.s_addr == g_dest_ip.s_addr )
            return PHSCAN_PORT_OPEN;
        else
            return PHSCAN_PORT_CLOSED;
    }
    return PHSCAN_PKT_UNRELATED;
}

/*
 * Checksums - IP and TCP
 */
unsigned short csum(uint16_t *ptr,int nbytes) 
{
    register long sum;
    uint16_t oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *( (uint8_t*) &oddbyte ) =* (uint8_t*) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void set_ip_spoofing(int spoof)
{
    g_spoofing = spoof;
}
