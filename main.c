/* main.c */

#include <stdlib.h>
#include <stdio.h>

#include "ssh/ssh.h"

int main(int argc, char **argv)
{
  char *server, *port;
  struct SSH_CONN *conn;
  
  if (argc < 2) {
    fprintf(stderr, "USAGE: %s server [port]\n", argv[0]);
    exit(1);
  }
  server = argv[1];
  port = (argc == 3) ? argv[2] : "22";

  if (ssh_init(0) < 0) {
    fprintf(stderr, "ERROR: %s\n", ssh_get_error());
    return 1;
  }    

  conn = ssh_conn_open(server, port);
  if (conn == NULL)
    fprintf(stderr, "ERROR: %s\n", ssh_get_error());
  else
    ssh_conn_close(conn);
  
  ssh_deinit();
  return 0;
}
