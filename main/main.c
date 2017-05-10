/* main.c */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <pwd.h>

#include "main/term.h"
#include "main/session.h"
#include "ssh/ssh.h"

#define HOST_KEY_STORE_FILE "host_keys.store"

static int read_password(const char *hostname, const char *username, char *password, size_t max_len, int retry)
{
  if (retry)
    printf("Bad password, try again.\n");
  printf("Password for %s: ", username);
  fflush(stdout);
  if (term_read_password(password, max_len) < 0)
    return -1;
  printf("\n");

  return 0;
}

static int check_server_identity(const char *hostname, const struct SSH_STRING *host_key)
{
  enum SSH_HOST_KEY_STORE_STATUS status;

  ssh_log("- checking identity of server '%s'\n", hostname);
  
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
    // other error, with error message already set
    return -1;
  }
}

static int get_cmdline_username_server(char *username, size_t username_len, char *server, size_t server_len, const char *cmdline_arg)
{
  const char *at;

  if ((at = strchr(cmdline_arg, '@')) == NULL) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
      printf("ERROR: can't read current username\n");
      return -1;
    }
    if (strlen(pw->pw_name) + 1 > username_len
        || strlen(cmdline_arg) + 1 > server_len) {
      printf("ERROR: string too long\n");
      return -1;
    }
    strcpy(username, pw->pw_name);
    strcpy(server, cmdline_arg);
  } else {
    if (at - cmdline_arg + 1 > username_len || strlen(at) > server_len) {
      printf("ERROR: string too large\n");
      return -1;
    }
    strncpy(username, cmdline_arg, at - cmdline_arg);
    username[at - cmdline_arg] = '\0';
    strcpy(server, at + 1);
  }
  return 0;
}

int main(int argc, char **argv)
{
  char username[512];
  char server[512];
  char *port;
  struct SSH_CHAN_CONFIG *chan_cfg;
  struct SSH_CONN_CONFIG conn_cfg;
  struct SSH_CONN *conn;

  if (argc < 2) {
    fprintf(stderr, "USAGE: %s [username@]server [port]\n", argv[0]);
    exit(1);
  }
  if (get_cmdline_username_server(username, sizeof(username), server, sizeof(server), argv[1]) < 0)
    return 1;
  port = (argc == 3) ? argv[2] : NULL;

  if (ssh_init(0) < 0
      || (chan_cfg = get_session_channel_config()) == NULL) {
    fprintf(stderr, "ERROR: %s\n", ssh_get_error());
    return 1;
  }

  // connection info
  conn_cfg.server = server;
  conn_cfg.port = port;
  conn_cfg.username = username;
  conn_cfg.version_software = NULL;
  conn_cfg.version_comments = NULL;
  conn_cfg.server_identity_checker = check_server_identity;
  conn_cfg.password_reader = read_password;

  // connect
  conn = ssh_conn_open(&conn_cfg);
  if (conn == NULL) {
    fprintf(stderr, "Error connecting: %s\n", ssh_get_error());
  } else {
    ssh_log("- connected!\n");

    if (ssh_conn_run(conn, 1, chan_cfg) < 0)
      fprintf(stderr, "Error: %s\n", ssh_get_error());
    ssh_conn_close(conn);
  }
  
  ssh_deinit();
  return 0;
}
