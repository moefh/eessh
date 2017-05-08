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
  ret = fgets(password, max_len, stdin);  // TODO: read() from STDIN_FILENO
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

/* ------------------------------------------------------------------ */
/* --- session stuff ------------------------------------------------ */

static int sess_init(struct SSH_CHAN *chan)
{
  if (isatty(STDIN_FILENO)) {
    // TODO:
    // - set STDIN_FILENO to O_NONBLOCK
    // - set terminal to raw
    // - atexit() revert terminal to normal
  }
  
  // we want to be notified when STDIN_FILENO has data available to read:
  if (ssh_chan_watch_fd(chan, STDIN_FILENO, SSH_CHAN_FD_READ) < 0)
    return -1;
  return 0;
}

static int sess_process_fd(struct SSH_CHAN *chan, int fd, uint8_t fd_flags)
{
  if (fd == STDIN_FILENO) {
    // TODO: read() from fd, ssh_chan_send() data
    return 0;
  }

  if (fd == STDOUT_FILENO) {
    // TODO: write() stderr buffer to fd, use ssh_chan_watch_fd() to
    // stop SSH_CHAN_FD_WRITE on STDOUT_FILENO if buffer empty
    return 0;
  }

  if (fd == STDERR_FILENO) {
    // TODO: write() stderr buffer to fd, use ssh_chan_watch_fd() to
    // stop SSH_CHAN_FD_WRITE on STDERR_FILENO if buffer empty
    return 0;
  }

  ssh_log("unexpected fd: %d\n", fd);
  return -1;
}

static int sess_got_data(struct SSH_CHAN *chan, void *data, size_t data_len)
{
  // TODO:
  // - add data to stdout buffer
  // - write() as much as possible of the buffer to STDOUT_FILENO
  // - use ssh_chan_watch_fd() to watch SSH_CHAN_FD_WRITE on STDOUT_FILENO if buffer not empty
  return 0;
}

static int sess_got_ext_data(struct SSH_CHAN *chan, uint32_t data_type_code, void *data, size_t data_len)
{
  if (data_type_code != SSH_EXTENDED_DATA_STDERR)
    ssh_log("WARNING: received ext data in unknown data_type_code=%u\n", data_type_code);
    
  // TODO:
  // - add data to stderr buffer
  // - write() as much as possible of the buffer to STDERR_FILENO
  // - use ssh_chan_watch_fd() to watch SSH_CHAN_FD_WRITE on STDERR_FILENO if buffer not empty
  return 0;
}

/* --- end session stuff -------------------------------------------- */
/* ------------------------------------------------------------------ */

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
  struct SSH_CONN_CONFIG conn_cfg;
  struct SSH_CHAN_CONFIG chan_cfg;
  struct SSH_CHAN_SESSION_CONFIG chan_session_cfg;
  struct SSH_CONN *conn;

  if (argc < 2) {
    fprintf(stderr, "USAGE: %s [username@]server [port]\n", argv[0]);
    exit(1);
  }
  if (get_username_server(username, sizeof(username), server, sizeof(server), argv[1]) < 0)
    return 1;
  port = (argc == 3) ? argv[2] : NULL;

  if (ssh_init(0) < 0) {
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

  // session info
  chan_cfg.type = SSH_CHAN_SESSION;
  chan_cfg.created = sess_init;
  chan_cfg.fd_ready = sess_process_fd;
  chan_cfg.received = sess_got_data;
  chan_cfg.received_ext = sess_got_ext_data;
  chan_cfg.type_config = &chan_session_cfg;
  chan_session_cfg.run_command = NULL;
  chan_session_cfg.alloc_pty = 1;
  chan_session_cfg.term = getenv("TERM");
  chan_session_cfg.term_width = 80;  // TODO: read terminal size
  chan_session_cfg.term_height = 25;

  // connect
  conn = ssh_conn_open(&conn_cfg);
  if (conn == NULL) {
    fprintf(stderr, "Error connecting: %s\n", ssh_get_error());
  } else {
    ssh_log("- connected!\n");

    if (ssh_conn_run(conn, 1, &chan_cfg) < 0)
      fprintf(stderr, "Error: %s\n", ssh_get_error());
    ssh_conn_close(conn);
  }
  
  ssh_deinit();
  return 0;
}
