/* network.c */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
#if 0
  struct hostent *srv_host;
  struct sockaddr_in srv_addr;
  int sock;

  srv_host = gethostbyname(server);
  if (srv_host == NULL) {
    ssh_set_error("can't resolve server '%s'", server);
    return -1;
  }

  memset(&srv_addr, 0, sizeof(srv_addr));
  srv_addr.sin_family = AF_INET;
  memcpy(&srv_addr.sin_addr.s_addr, srv_host->h_addr, srv_host->h_length);
  srv_addr.sin_port = htons(port);
#else
  struct addrinfo addr_hints;
  struct addrinfo *addr_result, *addr;
  int sock, ret;
  
  memset(&addr_hints, 0, sizeof(struct addrinfo));
  addr_hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  addr_hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  addr_hints.ai_flags = 0;
  addr_hints.ai_protocol = 0;          /* Any protocol */

  ret = getaddrinfo(server, port, &addr_hints, &addr_result);
  if (ret != 0) {
    ssh_set_error("getaddrinfo: %s", gai_strerror(ret));
    return -1;
  }

#endif

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

ssize_t ssh_net_read(int sock, void *data, size_t max_len)
{
  while (1) {
    ssize_t ret = read(sock, data, max_len);
    if (ret < 0 && errno == EINTR)
      continue;
    //dump_mem(data, ret, "**************** READ ***********************************");
    return ret;
  }
}

int ssh_net_read_all(int sock, void *data, size_t len)
{
  size_t cur = 0;

  while (cur < len) {
    ssize_t s = ssh_net_read(sock, (char *) data + cur, len - cur);
    if (s <= 0) {
      ssh_set_error("read error");
      return -1;
    }
    cur += s;
  }

  return 0;
}
