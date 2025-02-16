#include "headers/unix_net.h"
#include <fcntl.h>
#include <sys/ioctl.h>

void v_exec(char *command) {
  if (system(command)) {
    fprintf(stderr, "command %s \nerror %d: %s\n", command, errno,
            strerror(errno));
    exit(-1);
  }
}

void v_create_network_interface() {
  char command[1024];
#ifdef _AS_SERVER
  snprintf(command, sizeof(command), "ifconfig %s 10.14.88.0/24 mtu %d up",
           INTERFACE_NAME, MTU);
#endif
#ifdef _AS_CLIENT
  snprintf(command, sizeof(command), "ifconfig %s 10.14.88.1/24 mtu %d up",
           INTERFACE_NAME, MTU);
#endif
  v_exec(command);
}

void v_setup_route_table() {
  v_exec("sysctl -w net.ipv4.ip_forward=1");
  char command[1024];
#ifdef _AS_CLIENT
  snprintf(command, sizeof command,
           "ip route add %s via $(ip route | grep default | awk {'print $3'})",
           HOST_NAME);
  v_exec(command);
  snprintf(command, sizeof command, "ip route add 0.0.0.0/0 dev %s",
           INTERFACE_NAME);
  v_exec(command);
#endif
#ifdef _AS_SERVER
  v_exec("iptables -t nat -A POSTROUTING -s 10.14.88.0/24 ! -d 10.14.88.0/24 "
         "-m comment --comment 'berkeley_vpn' -j MASQUERADE");
  v_exec("iptables -A FORWARD -s 10.14.88.0/24 -m state --state "
         "RELATED,ESTABLISHED -j ACCEPT");
  v_exec("iptables -A FORWARD -d 10.14.88.0/24 -j ACCEPT");
#endif
}

void v_cleanup_route_table() {
  char command[1024];
#ifdef _AS_CLIENT
  snprintf(command, sizeof command, "ip route del %s", HOST_NAME);
  v_exec(command);
  v_exec("ip route del 0.0.0.0/0");
#endif
#ifdef _AS_SERVER
  v_exec("iptables -t nat -D POSTROUTING -s 10.14.88.0/24 ! -d 10.14.88.0/24 "
         "-m comment --comment 'berkeley_vpn' -j MASQUERADE");
  v_exec("iptables -D FORWARD -s 10.14.88.0/24 -m state --state "
         "RELATED,ESTABLISHED -j ACCEPT");
  v_exec("iptables -D FORWARD -d 10.14.88.0/24 -j ACCEPT");
#endif
  // for both client and server return settings to default
  v_exec("sysctl -w net.ipv4.ip_forward=0");
  snprintf(command, sizeof command, "ifconfig %s 10.14.88.0/24 mtu %d down",
           INTERFACE_NAME, MTU);
}
int fd_setup_tun_device(void) {
  struct ifreq ifr;
  int tun_fd, e;

  if ((tun_fd = open("/dev/net/tun", O_RDWR, S_IWUSR | S_IRUSR)) == -1) {
    fprintf(stderr, "Open /dev/net/tun error %d: %s\n", errno, strerror(errno));
    exit(_CRITICAL_ERROR_);
  }
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ);

  if ((e = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
    fprintf(stderr, "Ioctl TUNSETIFF error %d: %s\n", errno, strerror(errno));
    close(tun_fd);
    exit(_CRITICAL_ERROR_);
  }
  return tun_fd;
}

int create_connection(struct sockaddr *addr, socklen_t *addrlen) {
  int sock, flags;
  int e_code;
  struct addrinfo info;
  struct addrinfo *result;
  memset(&info, 0, sizeof info);
  info.ai_socktype = SOCK_DGRAM;
  info.ai_protocol = IPPROTO_UDP;

#ifdef _AS_SERVER
  const char *host = BIND_HOST;
#endif
#ifdef _AS_CLIENT
  const char *host = HOST_NAME;
#endif

  if ((e_code = getaddrinfo(host, NULL, &info, &result)) != 0) {
    fprintf(stderr, "getaddrinfo error %d: %s\n", e_code, gai_strerror(e_code));
    return _CRITICAL_ERROR_;
  }

  if (result->ai_family == AF_INET) {
    ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(PORT);
  } else if (result->ai_family == AF_INET6) {
    ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(PORT);
  } else {
    fprintf(stderr, "Unknown network family \n");
    return (_CRITICAL_ERROR_);
  }
  memcpy(addr, result->ai_addr, result->ai_addrlen);
  *addrlen = result->ai_addrlen;
  if ((sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(stderr, "socket creation error %d: %s\n", errno, strerror(errno));
    freeaddrinfo(result);
    return (_CRITICAL_ERROR_);
  }
#ifdef _AS_SERVER
  if (bind(sock, result->ai_addr, result->ai_addrlen) != 0) {
    fprintf(stderr, "bind()  error %d: %s\n", errno, strerror(errno));
    freeaddrinfo(result);
    return (_CRITICAL_ERROR_);
  }
#endif
  freeaddrinfo(result);
  flags = fcntl(sock, F_GETFL, 0);
  if (flags != -1) {
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1) {
      return sock;
    }
  }
  fprintf(stderr, "fcntl setflag error\n");
  close(sock);
  return (_CRITICAL_ERROR_);
}
