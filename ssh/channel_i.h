/* channel_i.h */

#ifndef CHANNEL_I_H_FILE
#define CHANNEL_I_H_FILE

#include <poll.h>

#include "ssh/channel.h"

#define MAX_POLL_FDS  8

enum SSH_CHAN_STATUS {
  SSH_CHAN_STATUS_CREATED,
  SSH_CHAN_STATUS_REQUESTED,
  SSH_CHAN_STATUS_OPEN,
  SSH_CHAN_STATUS_CLOSED,
};

struct SSH_CHAN {
  struct SSH_CONN *conn;
  void *userdata;
  enum SSH_CHAN_STATUS status;
  struct pollfd watch_fds[MAX_POLL_FDS];
  nfds_t num_watch_fds;

  uint32_t local_num;
  uint32_t remote_num;
  uint32_t local_max_packet_size;
  uint32_t local_window_size;
  uint32_t remote_max_packet_size;
  uint32_t remote_window_size;

  enum SSH_CHAN_TYPE type;
  void *type_config;
  ssh_chan_fn_open notify_open;
  ssh_chan_fn_open_failed notify_open_failed;
  ssh_chan_fn_closed notify_closed;
  ssh_chan_fn_fd_ready notify_fd_ready;
  ssh_chan_fn_received notify_received;
  ssh_chan_fn_received_ext notify_received_ext;
};

int ssh_chan_run_connection(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs);
void ssh_chan_free(struct SSH_CHAN *chan);

#endif /* CHANNEL_I_H_FILE */
