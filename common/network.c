/* network.c */

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common/network_i.h"

#include "common/error.h"

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

int ssh_net_write_all(int sock, const void *data, size_t len)
{
  size_t cur = 0;
  
  while (cur < len) {
    ssize_t s = write(sock, (char *) data + cur, len - cur);
    if (s < 0 && errno == EINTR)
      continue;
    if (s <= 0) {
      ssh_set_error("write error");
      return -1;
    }
    cur += s;
  }

  return 0;
}

ssize_t ssh_net_read(int sock, void *data, size_t len)
{
  ssize_t len_left;

  if (len > SSIZE_MAX) {
    ssh_set_error("read too large");
    errno = 0;
    return -1;
  }

  len_left = len;
  while (len_left > 0) {
    ssize_t ret = read(sock, data, len_left);
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
      return -1;
    }
    data += ret;
    len_left -= ret;
  }
  return len;
}
