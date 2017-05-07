/* main.c */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <pwd.h>

#include "ssh/ssh.h"

#define HOST_KEY_STORE_FILE "host_keys.store"

static int term_read_password(char *password, size_t max_len)
{
  struct termios old_term;
  int disable_echo;
  char *ret;

  disable_echo = isatty(STDIN_FILENO);
  if (disable_echo) {
    struct termios term;

    tcgetattr(STDIN_FILENO, &old_term);
    term = old_term;
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
  }
  ret = fgets(password, max_len, stdin);
  if (disable_echo)
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);

  if (ret == NULL)
    return -1;

  if ((ret = strchr(password, '\r')) != NULL)
    *ret = '\0';
  if ((ret = strchr(password, '\n')) != NULL)
    *ret = '\0';
  return 0;
}

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
    // other error, message already set
    return -1;
  }
}

static int get_username_server(char *username, size_t username_len, char *server, size_t server_len, const char *input)
{
  const char *at;

  if ((at = strchr(input, '@')) == NULL) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
      printf("ERROR: can't read current username\n");
      return -1;
    }
    if (strlen(pw->pw_name) + 1 > username_len
        || strlen(input) + 1 > server_len) {
      printf("ERROR: string too long\n");
      return -1;
    }
    strcpy(username, pw->pw_name);
    strcpy(server, input);
  } else {
    if (at - input + 1 > username_len || strlen(at) > server_len) {
      printf("ERROR: string too large\n");
      return -1;
    }
    strncpy(username, input, at - input);
    username[at - input] = '\0';
    strcpy(server, at + 1);
  }
  return 0;
}

int main(int argc, char **argv)
{
  char username[512];
  char server[512];
  char *port;
  struct SSH_CONN *conn;

  if (argc < 2) {
    fprintf(stderr, "USAGE: %s [username@]server [port]\n", argv[0]);
    exit(1);
  }
  if (get_username_server(username, sizeof(username), server, sizeof(server), argv[1]) < 0)
    return 1;
  port = (argc == 3) ? argv[2] : "22";

  if (ssh_init(0) < 0) {
    fprintf(stderr, "ERROR: %s\n", ssh_get_error());
    return 1;
  }

  conn = ssh_conn_new();
  if (conn == NULL)
    fprintf(stderr, "Error initializing connection: %s\n", ssh_get_error());
  else {
    ssh_conn_set_server_identity_checker(conn, check_server_identity);
    ssh_conn_set_username(conn, username);
    ssh_conn_set_password_reader(conn, read_password);
    if (ssh_conn_open(conn, server, port) < 0)
      fprintf(stderr, "Error connecting: %s\n", ssh_get_error());
    ssh_conn_free(conn);
  }
  
  ssh_deinit();
  return 0;
}
