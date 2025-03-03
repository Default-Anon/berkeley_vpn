#ifndef __UNIX_NET_H__
#define __UNIX_NET_H__
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

/* -------------------------------------------------------------*/
/* CHANGE IT AS YOU WISH FOR YOUR SETUP                         */
/* -------------------------------------------------------------*/
#define HOST_NAME "85.192.28.206" //|
#define PORT 54321                //|
#define MTU 1450                  //| MAX CAN BE 1518 bytes ETH!*/
#define INTERFACE_NAME "tun0"     //|
/* -------------------------------------------------------------*/

#define BIND_HOST "0.0.0.0"

/* -------------------------------------------------------------*/
/* If you install all requirments, don't touch it all must work */

// #define _UBUNTU_
#define _DEBIAN_
/* -------------------------------------------------------------*/

#define _CRITICAL_ERROR_ -1

void v_exec(char *command);

void v_create_network_interface(void);

void v_setup_route_table(void);

void v_cleanup_route_table(void);

int fd_setup_tun_device(void);

int create_connection(struct sockaddr *addr, socklen_t *addrlen);

#endif
