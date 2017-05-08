/* channel.c */

#include <stdlib.h>
#include <stdint.h>

#include "ssh/channel_i.h"

#include "ssh/connection_i.h"

#include "common/error.h"
#include "common/debug.h"
#include "ssh/debug.h"

struct SSH_CHAN {
  struct SSH_CONN *conn;
  uint32_t local_num;
  uint32_t remote_num;
  uint32_t max_packet_size;
  uint32_t window_size;
};

uint32_t ssh_chan_get_num(struct SSH_CHAN  *chan)
{
  return chan->local_num;
}

void ssh_chan_close(struct SSH_CHAN  *chan)
{
  ssh_log("ssh_chan_close() not implemented!\n");
}

ssize_t ssh_chan_send(struct SSH_CHAN *chan, void *data, size_t data_len)
{
  ssh_set_error("ssh_chan_send() not implemented!");
  return -1;
}

ssize_t ssh_chan_send_ext(struct SSH_CHAN *chan, uint32_t data_type_code, void *data, size_t data_len)
{
  ssh_set_error("ssh_chan_send_ext() not implemented!");
  return -1;
}

int ssh_chan_watch_fd(struct SSH_CHAN  *chan, int fd, uint8_t fd_flags)
{
  ssh_set_error("ssh_chan_watch_fd() not implemented!");
  return -1;
}

int ssh_chan_run_connection(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs)
{
  /*
   * TODO:
   * - open requested channels
   * - call 'created' on each channel
   * - poll() conn->sock and channel fds
   */
  
#if 1
  for (int i = 0; i < 1; i++) {
    struct SSH_BUF_READER *pack;

    pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return -1;
    }

    dump_packet_reader("received packet", pack, conn->in_stream.mac_len);
  }
#endif
  return 0;
}
