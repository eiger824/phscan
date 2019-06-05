#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "icmpping.h"
#include "common.h"

static struct connection* g_conns;
static size_t g_conn_count;
static size_t g_tasks_progress = 0;
// We need to have

uint16_t checksum(void *b, int len)
{	uint16_t *buf = b;
    uint32_t sum = 0;
    uint16_t result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}
int register_answer(struct connection* conns, size_t n, char* ip, int status)
{
    struct connection* h;
    size_t i;

    if (!conns || n == 0 || !ip)
        return PHSCAN_ERROR;
    for (i = 0; i < n; ++i)
    {
        h = &conns[i];
        if (!strcpy(h->ip, ip))
        {
            h->host_status = status;
            g_tasks_progress++;
            break;
        }
    }
    return g_tasks_progress == g_conn_count ? PHSCAN_SUCCESS : PHSCAN_ERROR;
}

int send_ping(const char* dest_ip)
{
    const int ttl_val = 0xff;
    int s, ret;
    size_t i;
    struct sockaddr_in addr;
    uint8_t buff[BUF_SEND_MAX];
    struct icmphdr* hdr;

    if ( (s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("sending socket() failed");
        return PHSCAN_ERROR;
    }
    if (setsockopt(s, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != PHSCAN_SUCCESS)
    {
        perror("setsockopt() failed");
        return PHSCAN_ERROR;
    }
    // Set this socket non-blocking
    if ( fcntl(s, F_SETFL, O_NONBLOCK) != PHSCAN_SUCCESS)
    {
        perror("fcntl() failed");
        return PHSCAN_ERROR;
    }
    // Fill in socket struct fields
    addr.sin_family = AF_INET; 
    addr.sin_port = 0; // Irrelevant
    addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Sending part
    memset(buff, 0, BUF_SEND_MAX);
    // Fill in ICMP header
    hdr = (struct icmphdr*)buff;
    hdr->type = ICMP_ECHO;
    hdr->un.echo.id = get_random_integer(1, USHRT_MAX);
    // Fill in some data in the message
    for (i = sizeof(struct icmphdr); i < BUF_SEND_MAX - 1; ++i)
        buff[i] = i + 48;
    buff[i] = '\0';
    hdr->un.echo.sequence = 0;
    hdr->checksum = checksum(buff, BUF_SEND_MAX);

    if ( (ret = sendto(s, buff, sizeof(buff), 0, (struct sockaddr*)&addr, sizeof(addr))) < 0 )
    {
        perror("sendto() failed");
        return ret;
    }
    return PHSCAN_SUCCESS;
}

int icmp_process_packet(uint8_t* buff, size_t size, char* ip)
{
    //TODO: implement
    struct iphdr* iph;
    struct icmphdr* icmph;
    struct in_addr src_addr, dst_addr;

    if (!buff || !ip || size == 0)
        return PHSCAN_HOST_DOWN;

    iph = (struct iphdr*)buff;
    icmph = (struct icmphdr*)(buff + iph->ihl * 4);

    src_addr.s_addr = iph->saddr;
    dst_addr.s_addr = iph->daddr;

    strcpy(ip, inet_ntoa(src_addr));

    dbg("Processing answer from: %s\n", inet_ntoa(src_addr) );

    // We should compare the ID, if it matches to the source ECHO sent
    // if (is_match(icmph->un.echo.id)

    return PHSCAN_HOST_UP;
}

void* icmp_thread_worker(void* data)
{
    struct icmp_thread_data* d = (struct icmp_thread_data*)data;
    size_t i;
    int ret;
    struct connection* h;

    ret = PHSCAN_SUCCESS;

    for (i = d->idx_start; i <= d->idx_stop; ++i)
    {
        h = &g_conns[i];
        ret |= send_ping(h->ip);
    }
    pthread_exit((void*)&ret);
}

void* icmp_thread_listen(void* data)
{
    int ret, status, s;
    ssize_t rb;
    struct sockaddr_in addr;
    uint8_t* buff;
    char src_ip[16];
    socklen_t sl;
    struct icmp_listen_data* d = (struct icmp_listen_data*)data;

    ret = PHSCAN_ERROR;
    buff = (uint8_t*) malloc (sizeof*buff * BUF_RECV_MAX);

    if ( (s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("listener socket() failed");
        ret = PHSCAN_ERROR;
        free(buff);
        pthread_exit((void*)&ret);
    }

    while ( ret != PHSCAN_SUCCESS )
    {
        dbg("g_task_progress = %zu\n", g_tasks_progress);
        sl = sizeof(addr);
        memset(buff, 0, BUF_RECV_MAX);
        if ( (rb = recvfrom(s, buff, BUF_RECV_MAX, 0, (struct sockaddr*)&addr, &sl)) > 0)
        {
            status = icmp_process_packet(buff, rb, src_ip);
            ret =  register_answer(d->conns, d->nconns, src_ip, status);
        }
        else
        {
            perror("recvfrom() failed");
        }
    }
    free(buff);
    pthread_exit((void*)&ret);
}

int icmp_run_tasks(struct connection* conns, size_t nr_tasks, int nr_threads)
{
    size_t tasks_per_thread;
    pthread_t threads[nr_threads];
    pthread_t listener;
    pthread_attr_t attrs;
    struct icmp_thread_data tdata[nr_threads];
    void* retval;
    int i, ret;
    struct icmp_listen_data td;

    if (!conns || nr_tasks == 0)
        return PHSCAN_ERROR;

    pthread_attr_init(&attrs);

    td.id = 0;
    td.conns = conns;
    td.nconns = nr_tasks;

    if (( ret = pthread_create(&listener, &attrs, icmp_thread_listen, (void*)&td)) != PHSCAN_SUCCESS)
    {
        perror("pthread_create() failed");
        return ret;
    }
    g_conns = conns;
    g_conn_count = nr_tasks;

    tasks_per_thread = nr_tasks / nr_threads;

    if (tasks_per_thread < 10)
    {
        dbg("Nr. tasks too low (%zu), using 1 thread\n", tasks_per_thread);
        nr_threads = 1;
    }

    for (i = 0; i < nr_threads; ++i)
    {
        tdata[i].id = 0;
        tdata[i].idx_start = i * tasks_per_thread;
        tdata[i].idx_stop = i < nr_threads - 1 ?
            (i + 1)* tasks_per_thread - 1 :
            nr_tasks - 1;
        if (pthread_create(&threads[i], &attrs, icmp_thread_worker, (void*)&tdata[i]) != PHSCAN_SUCCESS)
        {
            perror("pthread_create() failed");
            return PHSCAN_ERROR;
        }
    }
    ret = 0;
    for (i = 0; i < nr_threads; ++i)
    {
        pthread_join(threads[i], &retval);
        ret |= *(int*)retval;
    }
    // Wait for the listener to end
    pthread_join(listener, &retval);
    ret |= *(int*)retval;

    return ret;
}
