#ifndef __NET_H_
#define __NET_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define         MAX_INT_VAL     0xffffffff
#define         MIN_INT_VAL     0x00000000

int sockfds[8];

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

#endif   /* __NET_H */
