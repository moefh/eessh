/* channel.h */

#ifndef CHANNEL_H_FILE
#define CHANNEL_H_FILE

#include <stddef.h>
#include <stdint.h>

enum SSH_CHAN_TYPE {
  SSH_CHAN_TYPE_SESSION,
};

struct SSH_CHAN;
struct SSH_CONN;

/* watch fd_flags */
#define SSH_CHAN_FD_READ  (1<<0)
#define SSH_CHAN_FD_WRITE (1<<1)
#define SSH_CHAN_FD_CLOSE (1<<2)

typedef int (*ssh_chan_fn_open)(struct SSH_CHAN *chan, void *userdata);
typedef void (*ssh_chan_fn_open_failed)(struct SSH_CHAN *chan, void *userdata);
typedef void (*ssh_chan_fn_closed)(struct SSH_CHAN *chan, void *userdata);
typedef void (*ssh_chan_fn_received)(struct SSH_CHAN *chan, void *userdata, void *data, size_t data_len);
typedef void (*ssh_chan_fn_received_ext)(struct SSH_CHAN *chan, void *userdata, uint32_t data_type_code, void *data, size_t data_len);
typedef int (*ssh_chan_fn_fd_ready)(struct SSH_CHAN *chan, void *userdata, int fd, uint8_t fd_flags);
typedef int (*ssh_chan_fn_signal)(struct SSH_CHAN *chan, void *userdata);

struct SSH_CHAN_CONFIG {
  enum SSH_CHAN_TYPE type;
  void *userdata;
  ssh_chan_fn_open notify_open;
  ssh_chan_fn_open_failed notify_open_failed;
  ssh_chan_fn_closed notify_closed;
  ssh_chan_fn_fd_ready notify_fd_ready;
  ssh_chan_fn_received notify_received;
  ssh_chan_fn_received_ext notify_received_ext;
  ssh_chan_fn_signal notify_signal;
  void *type_config;
};

/* type_config for SSH_CHAN_SESSION */
struct SSH_CHAN_SESSION_CONFIG {
  const char *run_command;  // NULL to run default shell
  int alloc_pty;
  const char *term;
  uint32_t term_width;
  uint32_t term_height;
  /* TODO: encoded terminal modes */
};

uint32_t ssh_chan_get_num(struct SSH_CHAN  *chan);
int ssh_chan_watch_fd(struct SSH_CHAN  *chan, int fd, uint8_t enable_fd_flags, uint8_t disable_fd_flags);
void ssh_chan_close(struct SSH_CHAN  *chan);
ssize_t ssh_chan_send_data(struct SSH_CHAN *chan, void *data, size_t data_len);
ssize_t ssh_chan_send_ext_data(struct SSH_CHAN *chan, uint32_t data_type_code, void *data, size_t data_len);
void ssh_chan_notify_signal(void);

int ssh_chan_session_new_term_size(struct SSH_CHAN *chan, uint32_t new_term_width, uint32_t new_term_height);

#endif /* CHANNEL_H_FILE */
