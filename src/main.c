/*
 * @Source davidxn/simple_tun_demo
 * Goal: rewrite with adding cryptography
 */
#include "headers/unix_net.h"
#include <fcntl.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void v_signal_handler(int signo) {
  printf("Status: OFF\n");
  if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
    v_cleanup_route_table();
    exit(0);
  }
}

void v_setup_signal_handle() {
  struct sigaction sa;
  sa.sa_handler = &v_signal_handler;
  sa.sa_flags = SA_RESTART;
  sigfillset(&sa.sa_mask);

  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    perror("Cannot handle SIGHUP");
  }
  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("Cannot handle SIGINT");
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror("Cannot handle SIGTERM");
  }
}

void v_start_log(char *buf, size_t buf_sz) {
  time_t timer;
  time(&timer);
  if (snprintf(buf, buf_sz, "LOG STARTED:\t %s \n", ctime(&timer)) == -1) {
    fprintf(stderr, "Snprintf error %d: %s\n", errno, strerror(errno));
  }
}

void v_write_to_log(int log_fd, char *message, size_t message_len) {
  if (write(log_fd, message, message_len) == -1) {
    fprintf(stderr, "Write to log error %d: %s\n", errno, strerror(errno));
  }
}

int fd_create_log() {
  int fd = open("log.txt", O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
  char buf[512];
  if (fd == -1) {
    fprintf(stderr, "open log.txt error %d: %s\n", errno, strerror(errno));
    exit(_CRITICAL_ERROR_);
  }
  v_start_log(buf, sizeof buf);
  v_write_to_log(fd, buf, strlen(buf));
  v_exec("chmod +r log.txt");
  return fd;
}

void encrypt(char *tun_buf, char *udp_buf, size_t buf_sz) {
  memcpy(udp_buf, tun_buf, buf_sz);
}
void decrypt(char *udp_buf, char *tun_buf, size_t buf_sz) {
  memcpy(tun_buf, udp_buf, buf_sz);
}

int max(int a, int b) {
  if (a > b) {
    return a;
  }
  return b;
}

int main(int argc, char **argv) {
  int log_fd, udp_fd, tun_fd, max_fd;
  char tun_buf[MTU];
  char udp_buf[MTU];
  fd_set master, copy;
  int read_bytes = 0;
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof addr;
  tun_fd = fd_setup_tun_device();
  v_create_network_interface();
  v_setup_route_table();
  v_setup_signal_handle();
  log_fd = fd_create_log();

  udp_fd = create_connection((struct sockaddr *)&addr, &addr_len);

  if (udp_fd != _CRITICAL_ERROR_) {
    bzero(tun_buf, sizeof tun_buf);
    bzero(udp_buf, sizeof udp_buf);
    FD_ZERO(&master);
    FD_SET(tun_fd, &master);
    FD_SET(udp_fd, &master);
    int max_fd = max(tun_fd, udp_fd);
    max_fd++;
    while (1) {
      copy = master;
      if (select(max_fd, &copy, NULL, NULL, NULL) == -1) {
        fprintf(stderr, "select error %d: %s\n", errno, strerror(errno));
      }
      if (FD_ISSET(tun_fd, &copy)) {
        read_bytes = read(tun_fd, tun_buf, MTU);
        if (read_bytes < 0) {
          fprintf(stderr, "read error %d: %s\n", errno, strerror(errno));
          break;
        }
        encrypt(tun_buf, udp_buf, read_bytes);
        read_bytes = sendto(udp_fd, udp_buf, read_bytes, 0,
                            (struct sockaddr *)&addr, addr_len);
        if (read_bytes < 0) {
          fprintf(stderr, "sendto udp_fd error\n");
        }
      }
      if (FD_ISSET(udp_fd, &copy)) {
        read_bytes = recvfrom(udp_fd, udp_buf, MTU, 0, (struct sockaddr *)&addr,
                              &addr_len);
        if (read_bytes < 0) {
          fprintf(stderr, "recvfrom udp_fd error %d: %s\n", errno,
                  strerror(errno));
          break;
        }
        decrypt(udp_buf, tun_buf, read_bytes);
        read_bytes = write(tun_fd, tun_buf, read_bytes);
        if (read_bytes < 0) {
          fprintf(stderr, "write to /dev/net/tun error %d:%s\n", errno,
                  strerror(errno));
        }
      }
    }
  }

  close(tun_fd);
  close(log_fd);
  close(udp_fd);
  v_cleanup_route_table();
  return 0;
}
