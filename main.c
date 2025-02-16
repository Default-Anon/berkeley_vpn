/*
 * Project structure:
 *   implement logging
 *   inplement signal handle
 *   implement setup iptables rules and create network interface
 *   implement creating and using tun file
 *   implement udp connection
 *   implement removing iptables rules
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define _AS_CLIENT
// #define _AS_SERVER
#define _CRITICAL_ERROR_ -1
#define MTU 1400
#define INTERFACE_NAME "tun0"
#define HOST_NAME "22.192.19.35"
#define BIND_HOST "0.0.0.0"
#define PORT 54321

void
v_exec (char *command)
{
  if (system (command))
    {
      fprintf (stderr, "command %s \nerror %d: %s\n", command, errno,
               strerror (errno));
      exit (-1);
    }
}

void
v_setup_route_table ()
{
  v_exec ("sysctl -w net.ipv4.ip_forward=1");
  char command[1024];
#ifdef _AS_CLIENT
  snprintf (
      command, sizeof command,
      "ip route add %s via $(ip route | grep default | awk {'print $3'})",
      HOST_NAME);
  v_exec (command);
  snprintf (command, sizeof command, "ip route add 0.0.0.0/0 dev %s",
            INTERFACE_NAME);
  v_exec (command);
#endif
#ifdef _AS_SERVER
  v_exec ("iptables -t nat -A POSTROUTING -s 10.14.88.0/24 ! -d 10.14.88.0/24 "
          "-m comment --comment 'berkeley_vpn' -j MASQUERADE");
  v_exec ("iptables -A FORWARD -s 10.14.88.0/24 -m state --state "
          "RELATED,ESTABLISHED -j ACCEPT");
  v_exec ("iptables -A FORWARD -d 10.14.88.0/24 -j ACCEPT");
#endif
}

void
v_cleanup_route_table ()
{
  char command[1024];
#ifdef _AS_CLIENT
  snprintf (command, sizeof command, "ip route del %s", HOST_NAME);
  v_exec (command);
  v_exec ("ip route del 0.0.0.0/0");
#endif
#ifdef _AS_SERVER
  v_exec ("iptables -t nat -D POSTROUTING -s 10.14.88.0/24 ! -d 10.14.88.0/24 "
          "-m comment --comment 'berkeley_vpn' -j MASQUERADE");
  v_exec ("iptables -D FORWARD -s 10.14.88.0/24 -m state --state "
          "RELATED,ESTABLISHED -j ACCEPT");
  v_exec ("iptables -D FORWARD -d 10.14.88.0/24 -j ACCEPT");
#endif
  // for both client and server return settings to default
  v_exec ("sysctl -w net.ipv4.ip_forward=0");
  snprintf (command, sizeof command, "ifconfig %s 10.14.88.0/24 mtu %d down",
            INTERFACE_NAME, MTU);
}

void
v_signal_handler (int signo)
{
  printf ("Status: OFF\n");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM)
    {
      v_cleanup_route_table ();
      exit (0);
    }
}

void
v_setup_signal_handle ()
{
  struct sigaction sa;
  sa.sa_handler = &v_signal_handler;
  sa.sa_flags = SA_RESTART;
  sigfillset (&sa.sa_mask);

  if (sigaction (SIGHUP, &sa, NULL) < 0)
    {
      perror ("Cannot handle SIGHUP");
    }
  if (sigaction (SIGINT, &sa, NULL) < 0)
    {
      perror ("Cannot handle SIGINT");
    }
  if (sigaction (SIGTERM, &sa, NULL) < 0)
    {
      perror ("Cannot handle SIGTERM");
    }
}

void
v_create_network_interface ()
{
  char command[1024];
#ifdef _AS_SERVER
  snprintf (command, sizeof (command), "ifconfig %s 10.14.88.0/24 mtu %d up",
            INTERFACE_NAME, MTU);
#endif
#ifdef _AS_CLIENT
  snprintf (command, sizeof (command), "ifconfig %s 10.14.88.1/24 mtu %d up",
            INTERFACE_NAME, MTU);
#endif
  v_exec (command);
}

void
v_start_log (char *buf, size_t buf_sz)
{
  time_t timer;
  time (&timer);
  if (snprintf (buf, buf_sz, "LOG STARTED:\t %s \n", ctime (&timer)) == -1)
    {
      fprintf (stderr, "Snprintf error %d: %s\n", errno, strerror (errno));
    }
}

void
v_write_to_log (int log_fd, char *message, size_t message_len)
{
  if (write (log_fd, message, message_len) == -1)
    {
      fprintf (stderr, "Write to log error %d: %s\n", errno, strerror (errno));
    }
}

int
fd_create_log ()
{
  int fd = open ("log.txt", O_RDWR | O_CREAT | O_APPEND);
  char buf[512];
  if (fd == -1)
    {
      fprintf (stderr, "open log.txt error %d: %s\n", errno, strerror (errno));
      exit (_CRITICAL_ERROR_);
    }
  v_start_log (buf, sizeof buf);
  v_write_to_log (fd, buf, strlen (buf));
  v_exec ("chmod +r log.txt");
  return fd;
}

int
fd_setup_tun_device (void)
{
  struct ifreq ifr;
  int tun_fd, e;

  if ((tun_fd = open ("/dev/net/tun", O_RDWR)) == -1)
    {
      fprintf (stderr, "Open /dev/net/tun error %d: %s\n", errno,
               strerror (errno));
      exit (_CRITICAL_ERROR_);
    }
  memset (&ifr, 0, sizeof (ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy (ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ);

  if ((e = ioctl (tun_fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
      fprintf (stderr, "Ioctl TUNSETIFF error %d: %s\n", errno,
               strerror (errno));
      close (tun_fd);
      exit (_CRITICAL_ERROR_);
    }
  return tun_fd;
}

int
create_connection (struct sockaddr *addr, socklen_t *addrlen)
{
  int sock, flags;
  int e_code;
  struct addrinfo info;
  struct addrinfo *result;
  memset (&info, 0, sizeof info);
  info.ai_socktype = SOCK_DGRAM;
  info.ai_protocol = IPPROTO_UDP;

#ifdef _AS_SERVER
  const char *host = BIND_HOST;
#endif
#ifdef _AS_CLIENT
  const char *host = HOST_NAME;
#endif

  if ((e_code = getaddrinfo (host, NULL, &info, &result)) != 0)
    {
      fprintf (stderr, "getaddrinfo error %d: %s\n", e_code,
               gai_strerror (e_code));
      return _CRITICAL_ERROR_;
    }

  if (result->ai_family == AF_INET)
    {
      ((struct sockaddr_in *)result->ai_addr)->sin_port = htons (PORT);
    }
  else if (result->ai_family == AF_INET6)
    {
      ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons (PORT);
    }
  else
    {
      fprintf (stderr, "Unknown network family \n");
      return (_CRITICAL_ERROR_);
    }
  memcpy (addr, result->ai_addr, result->ai_addrlen);
  *addrlen = result->ai_addrlen;
  if ((sock = socket (result->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      fprintf (stderr, "socket creation error %d: %s\n", errno,
               strerror (errno));
      freeaddrinfo (result);
      return (_CRITICAL_ERROR_);
    }
#ifdef _AS_SERVER
  if (bind (sock, result->ai_addr, result->ai_addrlen) != 0)
    {
      fprintf (stderr, "bind()  error %d: %s\n", errno, strerror (errno));
      freeaddrinfo (result);
      return (_CRITICAL_ERROR_);
    }
#endif
  freeaddrinfo (result);
  flags = fcntl (sock, F_GETFL, 0);
  if (flags != -1)
    {
      if (fcntl (sock, F_SETFL, flags | O_NONBLOCK) != -1)
        {
          return sock;
        }
    }
  fprintf (stderr, "fcntl setflag error\n");
  close (sock);
  return (_CRITICAL_ERROR_);
}
void
encrypt (char *tun_buf, char *udp_buf, size_t buf_sz)
{
  memcpy (udp_buf, tun_buf, buf_sz);
}
void
decrypt (char *udp_buf, char *tun_buf, size_t buf_sz)
{
  memcpy (tun_buf, udp_buf, buf_sz);
}

int
max (int a, int b)
{
  if (a > b)
    {
      return a;
    }
  return b;
}

int
main (int argc, char **argv)
{
  int log_fd, udp_fd, tun_fd, max_fd;
  char tun_buf[MTU];
  char udp_buf[MTU];
  fd_set master, copy;
  int read_bytes = 0;
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof addr;
  tun_fd = fd_setup_tun_device ();
  v_create_network_interface ();
  v_setup_route_table ();
  v_setup_signal_handle ();
  log_fd = fd_create_log ();

  udp_fd = create_connection ((struct sockaddr *)&addr, &addr_len);

  if (udp_fd != _CRITICAL_ERROR_)
    {
      bzero (tun_buf, sizeof tun_buf);
      bzero (udp_buf, sizeof udp_buf);
      FD_ZERO (&master);
      FD_SET (tun_fd, &master);
      FD_SET (udp_fd, &master);
      int max_fd = max (tun_fd, udp_fd);
      max_fd++;
      while (1)
        {
          copy = master;
          if (select (max_fd, &copy, NULL, NULL, NULL) == -1)
            {
              fprintf (stderr, "select error %d: %s\n", errno,
                       strerror (errno));
            }
          if (FD_ISSET (tun_fd, &copy))
            {
              read_bytes = read (tun_fd, tun_buf, MTU);
              if (read_bytes < 0)
                {
                  fprintf (stderr, "read error %d: %s\n", errno,
                           strerror (errno));
                  break;
                }
              encrypt (tun_buf, udp_buf, read_bytes);
              read_bytes = sendto (udp_fd, udp_buf, read_bytes, 0,
                                   (struct sockaddr *)&addr, addr_len);
              if (read_bytes < 0)
                {
                  fprintf (stderr, "sendto udp_fd error\n");
                  break;
                }
            }
          if (FD_ISSET (udp_fd, &copy))
            {
              read_bytes = recvfrom (udp_fd, udp_buf, MTU, 0,
                                     (struct sockaddr *)&addr, &addr_len);
              if (read_bytes < 0)
                {
                  fprintf (stderr, "recvfrom udp_fd error %d: %s\n", errno,
                           strerror (errno));
                  break;
                }
              decrypt (udp_buf, tun_buf, read_bytes);
              read_bytes = write (tun_fd, tun_buf, read_bytes);
              if (read_bytes < 0)
                {
                  fprintf (stderr, "write to /dev/net/tun error %d:%s\n",
                           errno, strerror (errno));
                }
            }
        }
    }

  close (tun_fd);
  close (log_fd);
  close (udp_fd);
  v_cleanup_route_table ();
  return 0;
}
