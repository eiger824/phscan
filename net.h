#ifndef __NET_H_
#define __NET_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define         MAX_INT_VAL     0xffffffff
#define         MIN_INT_VAL     0x00000000

struct port_info
{
	uint16_t portno;
	int status; // 0=> closed, 1=> open
};

typedef struct host
{
    char hostname[1024];
    char ip[16];
    int dns_err;
    struct port_info* pinfo;
	size_t nports;
} host_t;

/*
 * Function:	        bits_2_ipaddr
 * Brief:	            Given a 32-bit numeric IPv4 address, it converts it to
                        the conventional XXX.XXX.XXX.XXX format
 * @param ipaddr_bits:	The IPv4 address to transform
 * @param ip:	        Pointer to the buffer to store the converted IP address
 * Returns:	            0 on success, 1 otherwise 
*/
int bits_2_ipaddr(uint32_t ipaddr_bits, char *ip);

/*
 * Function:	        ipaddr_2_bits
 * Brief:	            Given a string representation of an IPv4 address, it
                        outputs a 32-bit 
                        integer 
 * @param ipaddr_str:	Pointer to the string containing the IPv4 representation
 * Returns:	            The 32-bit representation of the input IPv4
*/
uint32_t ipaddr_2_bits(char *ipaddr_str);

int connect_to_host(char* host, uint16_t port, int msecs);
int do_dns_lookup(char * hostname , char* ip);
int is_ip(char* str);
int is_subnet(char* str);
int compute_ip_range(char* str, char* ip_start, size_t* count);

host_t* build_host_list(int argc, char** argv, int opt_index, size_t* n,
        uint16_t port_start, uint16_t port_stop);
void dump_host_info(host_t* host_list, size_t n);
void free_host_list(host_t* host_list, size_t n);


#endif   /* __NET_H */
