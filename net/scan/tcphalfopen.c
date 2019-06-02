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
#include "threads.h"

struct in_addr g_dest_ip;
static int g_spoofing = 0;

static void* wait_for_syn_ack(void* data);

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

void dump_packet(uint8_t* buffer, size_t size, size_t width)
{
    size_t i;
    size_t current_width = 0;
    for (i = 0; i < size; ++i)
    {
        if (current_width + 3 < width)
            current_width += 3;
        else
        {
            current_width = 0;
            printf("\n");
        }

        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

#if defined (__CYGWIN__ ) || defined(_WIN32)
void dump_ip_packet(struct ip* iph)
#else
void dump_ip_packet(struct iphdr* iph)
#endif
{
    if (!iph)
        return;

#if defined (__CYGWIN__ ) || defined(_WIN32)
    printf("iph->ihl = %u\n", iph->ip_hl);
    printf("iph->version = %u\n", iph->ip_v);
    printf("iph->tos = %u\n", iph->ip_tos);
    printf("iph->tot_len = %u\n", iph->ip_len); 
    printf("iph->id = 0x%x\n", iph->ip_id); 
    printf("iph->frag_off = 0x%x\n", iph->ip_off); 
    printf("iph->ttl = %u\n", iph->ip_ttl);
    printf("iph->protocol = %d\n", iph->ip_p);
    printf("iph->check = 0x%x\n", iph->ip_sum); 
    printf("iph->saddr = %u\n", iph->ip_src.s_addr); 
    printf("iph->daddr = %u\n", iph->ip_dst.s_addr); 
#else
    printf("iph->ihl = %u\n", iph->ihl);
    printf("iph->version = %u\n", iph->version);
    printf("iph->tos = %u\n", iph->tos);
    printf("iph->tot_len = %u\n", iph->tot_len); 
    printf("iph->id = 0x%x\n", iph->id); 
    printf("iph->frag_off = 0x%x\n", iph->frag_off); 
    printf("iph->ttl = %u\n", iph->ttl);
    printf("iph->protocol = %d\n", iph->protocol);
    printf("iph->check = 0x%x\n", iph->check); 
    printf("iph->saddr = %u\n", iph->saddr); 
    printf("iph->daddr = %u\n", iph->daddr); 
#endif
}

/*
   Method to sniff incoming packets and look for Ack replies
   */
int process_packet(uint8_t* buffer, int size, char* ip, port_t* port)
{
    //Get the IP Header part of this packet
#if defined (__CYGWIN__ ) || defined(_WIN32)
    struct ip *iph = (struct ip*)buffer;
#else
    struct iphdr *iph = (struct iphdr*)buffer;
#endif
    struct tcphdr *tcph;
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;

    if (size < 0 || !buffer)
        return PHSCAN_PKT_UNRELATED;

#if defined (__CYGWIN__ ) || defined(_WIN32)
    if (iph->ip_p== IPPROTO_TCP)
#else
    if (iph->protocol == IPPROTO_TCP)
#endif
    {
#if defined (__CYGWIN__ ) || defined(_WIN32)
        iphdrlen = iph->ip_hl*4;
#else
        iphdrlen = iph->ihl*4;
#endif

        tcph = (struct tcphdr*)(buffer + iphdrlen);

        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));

#if defined (__CYGWIN__ ) || defined(_WIN32)
        source.sin_addr.s_addr = iph->ip_src.s_addr;
        dest.sin_addr.s_addr = iph->ip_dst.s_addr;
#else
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
#endif

        // Remote host: inet_ntoa(source.sin_addr)
        strcpy(ip, inet_ntoa(source.sin_addr));
        // Remote port: ntohs(tcph->source)

#if defined (__CYGWIN__ ) || defined(_WIN32)
        *port = ntohs(tcph->th_sport);
#else
        *port = ntohs(tcph->source);
#endif 

        if (
#if defined (__CYGWIN__ ) || defined(_WIN32)
                tcph->th_flags == (TH_SYN | TH_ACK)
#else
                tcph->syn == 1 && tcph->ack == 1
#endif
                && source.sin_addr.s_addr == g_dest_ip.s_addr )
        {
            return PHSCAN_PORT_OPEN;
        }
        else
        {
            return PHSCAN_PORT_CLOSED;
        }
    }
    return PHSCAN_PKT_UNRELATED;
}

/*
 * Checksums - IP and TCP
 */
unsigned short chksum(uint16_t *ptr, int nbytes) 
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

/* Function: run_tasks
 * Will take in the whole array of 'n' tasks and execute them
 * (i.e., perform the connections)
 * */
int run_tasks(struct connection* conns, size_t n)
{
    int ret, s;
    //Datagram to represent the packet
    char datagram[4096];	
    //IP header
#if defined (__CYGWIN__ ) || defined(_WIN32)
    struct ip *iph = (struct ip*) datagram;
#else
    struct iphdr *iph = (struct iphdr *) datagram;
#endif
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in  dest;
    struct pseudo_header psh;

    struct connection* h;
    struct sniffer_thread_data rv;

    char source_ip[16];

    pthread_t rsp;
    pthread_attr_t attrs;

    if (!conns || n == 0)
        return PHSCAN_ERROR;

    //Create a raw socket
    if ( (s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP)) < 0 )
    {
        perror("socket() failed");
        return PHSCAN_ERROR;
    }

    // Fill in thread data structure
    rv.id = 0;
    rv.conns = conns;
    rv.nconns = n;

    pthread_attr_init(&attrs);

    // Start thread that will get the answer
    if ( (ret = pthread_create(&rsp, &attrs, wait_for_syn_ack, (void*)&rv)) != PHSCAN_SUCCESS)
    {
        perror ("pthread_create() failed");
        return PHSCAN_ERROR;
    }

    for (size_t i = 0; i < n; ++i)
    {
        h = &conns[i];

        g_dest_ip.s_addr = inet_addr(h->ip);

        if (g_spoofing)
            // Get a random IP
            get_random_ip(source_ip, sizeof(source_ip));
        else
            // Get our local IP
            get_local_ip( NULL, source_ip );


        memset (datagram, 0, 4096);	/* zero out the buffer */

        //Fill in the IP Header
#if defined (__CYGWIN__ ) || defined(_WIN32)
        iph->ip_hl = 5;
        iph->ip_v= 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
        iph->ip_id = htons (54321);	//Id of this packet
        iph->ip_off = htons(16384);
        iph->ip_ttl = 64;
        iph->ip_p = IPPROTO_TCP;
        iph->ip_sum = 0;		//Set to 0 before calculating checksum
        iph->ip_src.s_addr = inet_addr ( source_ip );	//Spoof the source ip address
        iph->ip_dst.s_addr = g_dest_ip.s_addr;

        iph->ip_sum = chksum ((unsigned short *) datagram, iph->ip_len >> 1);
#else
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
        iph->id = htons (54321);	//Id of this packet
        iph->frag_off = htons(16384);
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;		//Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
        iph->daddr = g_dest_ip.s_addr;

        iph->check = chksum ((unsigned short *) datagram, iph->tot_len >> 1);
#endif

        //TCP Header
#if defined (__CYGWIN__ ) || defined(_WIN32)
        tcph->th_sport = htons ( get_random_integer(1040, 60000) );
        tcph->th_dport = htons ( h->pinfo.portno );
        tcph->th_seq = htonl(1105024978);
        tcph->th_ack = 0;

        tcph->th_off = sizeof(struct tcphdr) / 4;
        tcph->th_flags = TH_SYN;

        tcph->th_win = htons ( 14600 );	// maximum allowed window size
        tcph->th_sum = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
        tcph->th_urp = 0;
#else
        tcph->source = htons ( get_random_integer(1040, 60000) );
        tcph->dest = htons ( h->pinfo.portno );
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
#endif

        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;

        if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("setsockopt() failed");
            return PHSCAN_ERROR;
        }

        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = g_dest_ip.s_addr;

#if defined (__CYGWIN__ ) || defined(_WIN32)
        tcph->th_dport = htons ( h->pinfo.portno );
        tcph->th_sum = 0;
#else
        tcph->dest = htons ( h->pinfo.portno );
        tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
#endif

        psh.source_address = inet_addr( source_ip );
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr) );

        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

#if defined (__CYGWIN__ ) || defined(_WIN32)
        tcph->th_sum = chksum( (unsigned short*) &psh , sizeof (struct pseudo_header));
#else
        tcph->check = chksum( (unsigned short*) &psh , sizeof (struct pseudo_header));
#endif

        //Send the packet
#if defined (__CYGWIN__ ) || defined(_WIN32)
        if ( sendto (s, datagram , sizeof(struct ip) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
#else
        if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
#endif
        {
            perror("sendto() failed");
            return PHSCAN_ERROR;
        }
    }

    // Wait until all tasks have been accounted for
    pthread_join(rsp, NULL);

    return PHSCAN_SUCCESS; 
}

static void* wait_for_syn_ack(void* data)
{
    int sock_raw, status, data_size;
    int ret = 1;
    struct sockaddr saddr;
    struct sniffer_thread_data* val = (struct sniffer_thread_data*)data;
    struct connection* connections = val->conns;
    char ip[16];
    port_t port;
    uint8_t* buffer = (uint8_t*) malloc(USHRT_MAX); //Its Big!

    dbg("Sniffer thread initialising\n");

    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);

    if (sock_raw < 0)
    {
        perror("socket() failed");
        free(buffer);
        return NULL;
    }

    socklen_t sl;
    while (ret != 0)
    {
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , USHRT_MAX, 0 , &saddr , &sl);

        if ( data_size < 0 )
        {
            perror("recvfrom() failed");
            free(buffer);
            return NULL;
        }
        //Now process the packet
        status = process_packet(buffer , data_size, ip, &port);
        if (status == PHSCAN_PORT_OPEN || status == PHSCAN_PORT_CLOSED)
        {
            ret = set_task_status(connections, val->nconns, ip, port, status);
        }
    }

    close(sock_raw);
    printf("Sniffer finished.");
    free(buffer);

    return NULL;
}
