/* session.c */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>

#include "main/session.h"

#include "main/term.h"
#include "ssh/ssh.h"

struct SESS_DATA {
  struct SSH_BUFFER stdin_buf;
  struct SSH_BUFFER stdout_buf;
  struct SSH_BUFFER stderr_buf;
};

static struct SESS_DATA sess_data;
static struct SSH_CHAN_SESSION_CONFIG chan_session_cfg;
static struct SSH_CHAN_CONFIG chan_cfg;
static volatile sig_atomic_t got_sigwinch;

static void handle_sigwinch(int signum)
{
  got_sigwinch = 1;
  ssh_chan_notify_signal();
  signal(SIGWINCH, handle_sigwinch);
}

static int set_fd_nonblock(int fd)
{
  int flags;

  if ((flags = fcntl(fd, F_GETFL)) < 0)
    return -1;
  if ((flags & O_NONBLOCK) == 0) {
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
      return -1;
  }
  return 0;
}

static int sess_init(struct SSH_CHAN *chan, void *userdata)
{
  struct SESS_DATA *sess = userdata;
  
  ssh_log("- channel session open\n");

  sess->stdin_buf = ssh_buf_new();
  sess->stdout_buf = ssh_buf_new();
  sess->stderr_buf = ssh_buf_new();

  // we want to be notified when STDIN_FILENO has data available to read:
  if (ssh_chan_watch_fd(chan, STDIN_FILENO, SSH_CHAN_FD_READ, 0) < 0
      || ssh_chan_watch_fd(chan, STDOUT_FILENO, SSH_CHAN_FD_WRITE, 0) < 0
      || ssh_chan_watch_fd(chan, STDERR_FILENO, SSH_CHAN_FD_WRITE, 0) < 0)
    return -1;

  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "==== Press CTRL+Q to quit =============================================\r\n");
  ssh_buf_append_cstring(&sess->stdout_buf, "=======================================================================\r\n");
  
  if (set_fd_nonblock(STDIN_FILENO) < 0
      || set_fd_nonblock(STDOUT_FILENO) < 0
      || set_fd_nonblock(STDERR_FILENO) < 0) {
    ssh_set_error("error setting stdin/stdout/stderr to non-block");
    return -1;
  }
  if (isatty(STDIN_FILENO)) {
    if (term_setup_raw() < 0) {
      ssh_set_error("error in terminal setup");
      return -1;
    }
    signal(SIGWINCH, handle_sigwinch);
  }
  
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
  signal(SIGWINCH, SIG_IGN);

  ssh_buf_free(&sess->stdin_buf);
  ssh_buf_free(&sess->stdout_buf);
  ssh_buf_free(&sess->stderr_buf);
  term_restore();
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

static int sess_process_fd(struct SSH_CHAN *chan, void *userdata, int fd, uint8_t fd_flags)
{
  struct SESS_DATA *sess = userdata;

  //ssh_log("- processing fd %d with flags %d\n", fd, fd_flags);
  
  if (fd == STDIN_FILENO) {
    ssize_t sent;
    int r = read_stdin(&sess->stdin_buf, 1024);
    if (r < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
      return 0;
    }
    if (r == 0 && (fd_flags & SSH_CHAN_FD_CLOSE) != 0) {
      ssh_log("- stdin was closed, closing channel\n");
      ssh_chan_close(chan);
      return 0;
    }
    if (sess->stdin_buf.len > 0 && sess->stdin_buf.data[0] == 'Q' + 1 - 'A') {
      ssh_log("- CTRL+Q detected, closing channel\n");
      ssh_chan_close(chan);
      return 0;
    }
    if ((sent = ssh_chan_send_data(chan, sess->stdin_buf.data, sess->stdin_buf.len)) < 0)
      return -1;
    ssh_buf_remove_data(&sess->stdin_buf, 0, sent);
    return 0;
  }

  if (fd == STDOUT_FILENO) {
    if (write_out_buffer(chan, STDOUT_FILENO, &sess->stdout_buf) < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
    }
    return 0;
  }
  
  if (fd == STDERR_FILENO) {
    if (write_out_buffer(chan, STDERR_FILENO, &sess->stderr_buf) < 0) {
      ssh_log("ERROR: %s\n", ssh_get_error());
      ssh_chan_close(chan);
    }      
    return 0;
  }

  ssh_log("unexpected fd notification: %d\n", fd);
  return 0;
}

static void sess_got_data(struct SSH_CHAN *chan, void *userdata, void *data, size_t data_len)
{
  struct SESS_DATA *sess = userdata;

  if (data_len == 0)
    return;
  
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

static int sess_got_signal(struct SSH_CHAN *chan, void *userdata)
{
  int term_width, term_height;

  if (! got_sigwinch)
    return 0;
  got_sigwinch = 0;
  
  if (term_get_window_size(&term_width, &term_height) < 0) {
    ssh_log("warning: can't get new terminal window size; ignoring");
    return 0;
  }

  return ssh_chan_session_new_term_size(chan, term_width, term_height);
}

struct SSH_CHAN_CONFIG *get_session_channel_config(void)
{
  int term_width, term_height;

  if (term_get_window_size(&term_width, &term_height) < 0) {
    ssh_set_error("error reading terminal window size");
    return NULL;
  }

  chan_cfg.type = SSH_CHAN_TYPE_SESSION;
  chan_cfg.notify_open = sess_init;
  chan_cfg.notify_open_failed = sess_open_failed;
  chan_cfg.notify_closed = sess_close;
  chan_cfg.notify_fd_ready = sess_process_fd;
  chan_cfg.notify_received = sess_got_data;
  chan_cfg.notify_received_ext = sess_got_ext_data;
  chan_cfg.notify_signal = sess_got_signal;
  chan_cfg.userdata = &sess_data;
  chan_cfg.type_config = &chan_session_cfg;
  chan_session_cfg.run_command = NULL;  // run default user shell
  chan_session_cfg.alloc_pty = 1;
  chan_session_cfg.term = getenv("TERM");
  chan_session_cfg.term_width = term_width;
  chan_session_cfg.term_height = term_height;

  return &chan_cfg;
}
