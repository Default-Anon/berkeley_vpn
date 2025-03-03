/*
*License

The MIT License (MIT)

Copyright (c) 2016 lxd.me

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*/

#include "headers/security.h"
#include "headers/unix_net.h"
#include <fcntl.h>
#include <ifaddrs.h>
#include <openssl/aes.h>
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

void v_how_to_use(void) {
  printf("vpn <vpn.key>\n"
         "for creating a key use\n\t"
         "dd if=/dev/urandom of=vpn.key count=1 bs=32\n"
         "base64 < vpn.key \t\\\\copy it in secure way\n"
         "echo <your-clip-key> | base64 --decode > vpn.key\n");
  printf("HINT: change src/headers/unix_net.h for your personal use\n");
}

int fd_init_key(struct Crypter *crypt) {
  int fd = open("vpn.key", O_RDWR, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    v_exec("dd if=/dev/urandom of=vpn.key count=1 bs=32");
    fd = open("vpn.key", O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1) {
      fprintf(stderr, "open() error: %d, %s\n", errno, strerror(errno));
      v_how_to_use();
      exit(_CRITICAL_ERROR_);
    }
    v_exec("chmod +666 vpn.key");
  }
  read(fd, crypt->userkey, KEY_BYTE_LEN);
  read(fd, crypt->ivec, IV_BYTE_LEN);
  return fd;
}

int main(int argc, char **argv) {
  if (argc > 1) {
    v_how_to_use();
  }
  struct Crypter crypt;
  int key_fd, udp_fd, tun_fd, max_fd;
  int encrypt_read_bytes = 0, decrypt_read_bytes = 0;
  unsigned char tun_buf[MTU];
  unsigned char udp_buf[MTU];
  fd_set master, copy;
  int read_bytes = 0;
  struct sockaddr_storage addr;
  struct timeval timer;
  socklen_t addr_len = sizeof addr;
  key_fd = fd_init_key(&crypt);
  AES_set_encrypt_key(crypt.userkey, AES_128, &crypt.key);
  tun_fd = fd_setup_tun_device();
  v_create_network_interface();
  v_setup_route_table();
  v_setup_signal_handle();

  udp_fd = create_connection((struct sockaddr *)&addr, &addr_len);

  if (udp_fd != _CRITICAL_ERROR_) {
    bzero(tun_buf, sizeof tun_buf);
    bzero(udp_buf, sizeof udp_buf);
    FD_ZERO(&master);
    FD_SET(tun_fd, &master);
    FD_SET(udp_fd, &master);
    max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;
    max_fd++;
    timer.tv_usec = 100;
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
        encrypt_read_bytes = i_encrypt(tun_buf, udp_buf, read_bytes, crypt);
        read_bytes = sendto(udp_fd, udp_buf, encrypt_read_bytes, 0,
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
        decrypt_read_bytes = i_decrypt(udp_buf, tun_buf, read_bytes, crypt);
        read_bytes = write(tun_fd, tun_buf, decrypt_read_bytes);
        if (read_bytes < 0) {
          fprintf(stderr, "write to /dev/net/tun error %d:%s\n", errno,
                  strerror(errno));
        }
      }
    }
  }

  close(tun_fd);
  close(key_fd);
  close(udp_fd);
  v_cleanup_route_table();
  return 0;
}
