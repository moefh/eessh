/* main.c */

#include <stdlib.h>
#include <stdio.h>

#include "ssh/ssh.h"

#define HOST_KEY_STORE_FILE "host_keys.store"

static int check_host_identity(const char *hostname, const struct SSH_STRING *host_key)
{
  enum SSH_HOST_KEY_STORE_STATUS status;

  ssh_log("- checking identity of host '%s'\n", hostname);
  status = ssh_host_key_store_check_server(HOST_KEY_STORE_FILE, hostname, host_key);
  switch (status) {
  case SSH_HOST_KEY_STORE_STATUS_OK:
    ssh_log("- server identity confirmed\n");
    return 0;

  case SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND:
    ssh_log("- server identity not found, adding\n");
    if (ssh_host_key_store_add(HOST_KEY_STORE_FILE, hostname, host_key) < 0)
      ssh_log("WARNING: error saving server key in file '%s': %s\n", HOST_KEY_STORE_FILE, ssh_get_error());
    return 0;

  case SSH_HOST_KEY_STORE_STATUS_ERR_BAD_IDENTITY:
    ssh_set_error("server key for '%s' doesn't match the stored key", hostname);
    return -1;
    
  default:
    // other error, message already set
    return -1;
  }
}

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

  conn = ssh_conn_new();
  if (conn == NULL)
    fprintf(stderr, "Error initializing connection: %s\n", ssh_get_error());
  else {
    ssh_conn_set_host_key_checker(conn, check_host_identity);
    if (ssh_conn_open(conn, server, port) < 0)
      fprintf(stderr, "Error connecting: %s\n", ssh_get_error());
    ssh_conn_free(conn);
  }
  
  ssh_deinit();
  return 0;
}
