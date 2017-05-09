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

#include "ssh/ssh.h"

#define HOST_KEY_STORE_FILE "host_keys.store"

struct SESS_DATA {
  struct SSH_BUFFER stdin_buf;
  struct SSH_BUFFER stdout_buf;
  struct SSH_BUFFER stderr_buf;
};

static int restored_old_term = 0;
static struct termios old_term;

static void restore_term(void)
{
  if (! restored_old_term) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    restored_old_term = 1;
  }
}

static int set_stdin_nonblock(void)
{
  int flags;

  if ((flags = fcntl(STDIN_FILENO, F_GETFL)) < 0)
    return -1;
  if ((flags & O_NONBLOCK) == 0) {
    flags |= O_NONBLOCK;
    if (fcntl(STDIN_FILENO, F_SETFL, flags) < 0)
      return -1;
  }
  return 0;
}

static int setup_term(void)
{
  struct termios term;

  if (tcgetattr(STDIN_FILENO, &old_term) < 0)
    return -1;
  term = old_term;
  term.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
  term.c_oflag &= ~OPOST;
  term.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  term.c_cflag &= ~(CSIZE | PARENB);
  term.c_cflag |= CS8;
  term.c_cc[VMIN] = 0;
  term.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) < 0
      || atexit(restore_term) != 0)
    return -1;
  return 0;
}

static int sess_init(struct SSH_CHAN *chan, void *userdata)
{
  struct SESS_DATA *sess = userdata;
  
  ssh_log("- channel session open\n");

  sess->stdin_buf = ssh_buf_new();
  sess->stdout_buf = ssh_buf_new();
  sess->stderr_buf = ssh_buf_new();

  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "==== Press CTRL+Q to quit =============================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  
  if (set_stdin_nonblock() < 0) {
    ssh_set_error("error setting STDIN to non-block");
    return -1;
  }
  if (isatty(STDIN_FILENO)) {
    if (setup_term() < 0) {
      ssh_set_error("error in terminal setup");
      return -1;
    }
  }
  
  // we want to be notified when STDIN_FILENO has data available to read:
  if (ssh_chan_watch_fd(chan, STDIN_FILENO, SSH_CHAN_FD_READ, 0) < 0
      || ssh_chan_watch_fd(chan, STDOUT_FILENO, SSH_CHAN_FD_WRITE, 0) < 0
      || ssh_chan_watch_fd(chan, STDERR_FILENO, SSH_CHAN_FD_WRITE, 0) < 0)
    return -1;
  return 0;
}

static void sess_open_failed(struct SSH_CHAN *chan, void *userdata)
{
  ssh_log("- failed open channel\n");
}

static void sess_close(struct SSH_CHAN *data, void *userdata)
{
  struct SESS_DATA *sess = userdata;

  ssh_log("- channel session closed\n");

  ssh_buf_free(&sess->stdin_buf);
  ssh_buf_free(&sess->stdout_buf);
  ssh_buf_free(&sess->stderr_buf);
  restore_term();
}

static ssize_t read_stdin(struct SSH_BUFFER *buf, size_t len)
{
  size_t initial_len = buf->len;

  if (ssh_buf_grow(buf, len) < 0)
    return -1;
  while (len > 0) {
    ssize_t r = read(STDIN_FILENO, buf->data + buf->len, len);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EWOULDBLOCK || errno == EAGAIN)
        return buf->len - initial_len;
      ssh_set_error("error reading from stdin");
      return -1;
    }
    if (r == 0)
      break;
    len -= r;
    buf->len += r;
  }
  return buf->len - initial_len;
}

static int write_out_buffer(struct SSH_CHAN *chan, int out_fd, struct SSH_BUFFER *buf)
{
  while (buf->len > 0) {
    ssize_t w = write(out_fd, buf->data, buf->len);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EWOULDBLOCK || errno == EAGAIN)
        break;
    }
    if (w == 0)
      break;
    if (ssh_buf_remove_data(buf, 0, w) < 0)
      return -1;
  }
  
  if (buf->len == 0 && ssh_chan_watch_fd(chan, out_fd, 0, SSH_CHAN_FD_WRITE) < 0)
    return -1;
  if (buf->len > 0 && ssh_chan_watch_fd(chan, out_fd, SSH_CHAN_FD_WRITE, 0) < 0)
    return -1;
  return 0;
}

static void sess_process_fd(struct SSH_CHAN *chan, void *userdata, int fd, uint8_t fd_flags)
{
  struct SESS_DATA *sess = userdata;

  //ssh_log("- processing fd %d with flags %d\n", fd, fd_flags);
  
  if (fd == STDIN_FILENO) {
    int r = read_stdin(&sess->stdin_buf, 1024);
    if (r < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
      return;
    }
    if (r == 0 && (fd_flags & SSH_CHAN_FD_CLOSE) != 0) {
      ssh_log("- stdin was closed, closing channel\n");
      ssh_chan_close(chan);
      return;
    }
    if (sess->stdin_buf.len > 0 && sess->stdin_buf.data[0] == 'Q' + 1 - 'A') {
      ssh_log("- CTRL+Q detected, closing channel\n");
      ssh_chan_close(chan);
      return;
    }
    if (ssh_chan_send(chan, sess->stdin_buf.data, sess->stdin_buf.len) < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
    }
    ssh_buf_clear(&sess->stdin_buf);
    return;
  }

  if (fd == STDOUT_FILENO) {
    if (write_out_buffer(chan, STDOUT_FILENO, &sess->stdout_buf) < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
    }
    return;
  }
  
  if (fd == STDERR_FILENO) {
    if (write_out_buffer(chan, STDERR_FILENO, &sess->stderr_buf) < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
    }      
    return;
  }

  ssh_log("unexpected fd notification: %d\n", fd);
}

static void sess_got_data(struct SSH_CHAN *chan, void *userdata, void *data, size_t data_len)
{
  struct SESS_DATA *sess = userdata;

  if (ssh_buf_append_data(&sess->stdout_buf, data, data_len) < 0
      || write_out_buffer(chan, STDOUT_FILENO, &sess->stdout_buf) < 0) {
    ssh_log("ERROR: %s\n", ssh_get_error());
    ssh_chan_close(chan);
  }
}

static void sess_got_ext_data(struct SSH_CHAN *chan, void *userdata, uint32_t data_type_code, void *data, size_t data_len)
{
  struct SESS_DATA *sess = userdata;

  if (data_type_code != SSH_EXTENDED_DATA_STDERR) {
    ssh_log("WARNING: ignoring received ext data in unknown data_type_code=%u\n", data_type_code);
    return;
  }
  
  if (ssh_buf_append_data(&sess->stderr_buf, data, data_len) < 0
      || write_out_buffer(chan, STDERR_FILENO, &sess->stderr_buf) < 0) {
    ssh_log("ERROR: %s\n", ssh_get_error());
    ssh_chan_close(chan);
  }
}

/* ------------------------------------------------------------------ */

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
  struct SESS_DATA sess_data;
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
  chan_cfg.type = SSH_CHAN_TYPE_SESSION;
  chan_cfg.notify_open = sess_init;
  chan_cfg.notify_open_failed = sess_open_failed;
  chan_cfg.notify_closed = sess_close;
  chan_cfg.notify_fd_ready = sess_process_fd;
  chan_cfg.notify_received = sess_got_data;
  chan_cfg.notify_received_ext = sess_got_ext_data;
  chan_cfg.userdata = &sess_data;
  chan_cfg.type_config = &chan_session_cfg;
  chan_session_cfg.run_command = NULL;  // run default user shell
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
