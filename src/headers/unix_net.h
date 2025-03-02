#ifndef __UNIX_NET_H__
#define __UNIX_NET_H__
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define _AS_CLIENT
// #define _AS_SERVER
#define _CRITICAL_ERROR_ -1
#define MTU 1400
#define INTERFACE_NAME "tun0"
#define HOST_NAME "1.1.1.129"
#define BIND_HOST "0.0.0.0"
#define PORT 54321
#define MAGIC_CRYPT_NUMBER 0b11011011

void v_exec (char *command);

void v_create_network_interface (void);

void v_setup_route_table (void);

void v_cleanup_route_table (void);

int fd_setup_tun_device (void);

int create_connection (struct sockaddr *addr, socklen_t *addrlen);
