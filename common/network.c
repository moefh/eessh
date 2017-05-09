/* network.c */

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common/network_i.h"

#include "common/error.h"
#include "common/debug.h"

static int make_socket(int family, int socktype, int protocol)
{
  while (1) {
    int sock = socket(family, socktype, protocol);
    if (sock >= 0)
      return sock;
    if (errno != EINTR)
      return -1;
  }
}

static int make_connection(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
  while (1) {
    if (connect(sock, addr, addrlen) == 0)
      return 0;
    if (errno != EINTR)
      return -1;
  }
}

int ssh_net_set_sock_blocking(int sock, int block)
{
  int flags;

  flags = fcntl(sock, F_GETFL);
  if (flags < 0) {
    ssh_set_error("fcntl(): can't read socket flags");
    return -1;
  }

  if (block) {
    if ((flags & O_NONBLOCK) == 0)
      return 0; // already blocking
    flags &= ~O_NONBLOCK;
  } else {
    if ((flags & O_NONBLOCK) != 0)
      return 0; // already non-blocking
    flags |= O_NONBLOCK;
  }

  if (fcntl(sock, F_SETFL, flags) < 0) {
    ssh_set_error("fcntl(): can't set socket flags");
    return -1;
  }

  return 0;
}

int ssh_net_connect(const char *server, const char *port)
{
  struct addrinfo addr_hints;
  struct addrinfo *addr_result, *addr;
  int sock, ret;
  
  memset(&addr_hints, 0, sizeof(struct addrinfo));
  addr_hints.ai_family = AF_UNSPEC;    /* IPv4 or IPv6 */
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_flags = 0;
  addr_hints.ai_protocol = 0;

  ret = getaddrinfo(server, port, &addr_hints, &addr_result);
  if (ret != 0) {
    ssh_set_error("can't resolve server '%s', port '%s': %s", server, port, gai_strerror(ret));
    return -1;
  }

  sock = -1;
  for (addr = addr_result; addr != NULL; addr = addr->ai_next) {
    sock = make_socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0)
      continue;
    if (make_connection(sock, addr->ai_addr, addr->ai_addrlen) == 0)
      break;
    close(sock);
    sock = -1;
  }

  freeaddrinfo(addr_result);
  if (sock < 0)
    ssh_set_error("can't connect to server");
  return sock;
}

ssize_t ssh_net_write(int sock, const void *data, size_t len)
{
  ssize_t len_left;
  const uint8_t *p;

  if (len > SSIZE_MAX) {
    ssh_set_error("write too large");
    errno = 0;
    return -1;
  }

  p = data;
  len_left = len;
  while (len_left > 0) {
    ssize_t s = write(sock, p, len_left);
    if (s < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EWOULDBLOCK || errno == EAGAIN)
        return len - len_left;
      ssh_set_error("write error");
      return -1;
    }
    if (s == 0)
      return len - len_left;
    p += s;
    len_left -= s;
  }

  return len;
}

ssize_t ssh_net_read(int sock, void *data, size_t len)
{
  ssize_t len_left;
  uint8_t *p;

  if (len > SSIZE_MAX) {
    ssh_set_error("read too large");
    errno = 0;
    return -1;
  }

  p = data;
  len_left = len;
  while (len_left > 0) {
    ssize_t ret = read(sock, p, len_left);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EWOULDBLOCK || errno == EAGAIN)
        return len - len_left;
      ssh_set_error("read error");
      return -1;
    }
    if (ret == 0) {
      ssh_set_error("connection closed");
      errno = 0;
      return -1;
    }
    p += ret;
    len_left -= ret;
  }
  return len;
}
