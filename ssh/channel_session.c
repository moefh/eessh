/* channel_session.c */

#include <stdlib.h>
#include <stdint.h>

#include "ssh/channel_session_i.h"

#include "ssh/connection_i.h"
#include "ssh/channel_i.h"

#include "common/debug.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"

int ssh_chan_session_opened(struct SSH_CHAN *chan)
{
  struct SSH_CHAN_SESSION_CONFIG *cfg = chan->type_config;
  struct SSH_BUFFER *pack;
  
  if (cfg->alloc_pty) {
    if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
        || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_REQUEST) < 0
        || ssh_buf_write_u32(pack, chan->remote_num) < 0
        || ssh_buf_write_cstring(pack, "pty-req") < 0
        || ssh_buf_write_u8(pack, 0) < 0
        || ssh_buf_write_cstring(pack, cfg->term) < 0
        || ssh_buf_write_u32(pack, cfg->term_width) < 0
        || ssh_buf_write_u32(pack, cfg->term_height) < 0
        || ssh_buf_write_u32(pack, 0) < 0   // width pixels
        || ssh_buf_write_u32(pack, 0) < 0   // height pixels
        || ssh_buf_write_cstring(pack, "") < 0
        || ssh_conn_send_packet(chan->conn) < 0)
      return -1;
  }
  
  if (cfg->run_command == NULL) {
    if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
        || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_REQUEST) < 0
        || ssh_buf_write_u32(pack, chan->remote_num) < 0
        || ssh_buf_write_cstring(pack, "shell") < 0
        || ssh_buf_write_u8(pack, 1) < 0
        || ssh_conn_send_packet(chan->conn) < 0)
      return -1;
  } else {
    if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
        || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_REQUEST) < 0
        || ssh_buf_write_u32(pack, chan->remote_num) < 0
        || ssh_buf_write_cstring(pack, "exec") < 0
        || ssh_buf_write_u8(pack, 1) < 0
        || ssh_buf_write_cstring(pack, cfg->run_command) < 0
        || ssh_conn_send_packet(chan->conn) < 0)
      return -1;
  }

  return 0;
}

int ssh_chan_session_process_packet(struct SSH_CHAN *chan, struct SSH_BUF_READER *pack)
{
  switch (ssh_packet_get_type(pack)) {
  case SSH_MSG_CHANNEL_SUCCESS:
    chan->status = SSH_CHAN_STATUS_OPEN;
    if (chan->notify_open(chan, chan->userdata) < 0)
      ssh_chan_close(chan);
    break;

  default:
    dump_packet_reader("unhandled channel packet", pack, chan->conn->in_stream.mac_len);
  }

  return 0;
}

int ssh_chan_session_new_term_size(struct SSH_CHAN *chan, uint32_t new_term_width, uint32_t new_term_height)
{
  struct SSH_BUFFER *pack;

  if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
      || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_REQUEST) < 0
      || ssh_buf_write_u32(pack, chan->remote_num) < 0
      || ssh_buf_write_cstring(pack, "window-change") < 0
      || ssh_buf_write_u8(pack, 0) < 0
      || ssh_buf_write_u32(pack, new_term_width) < 0
      || ssh_buf_write_u32(pack, new_term_height) < 0
      || ssh_buf_write_u32(pack, 0) < 0  // width pixels
      || ssh_buf_write_u32(pack, 0) < 0 // height pixels
      || ssh_conn_send_packet(chan->conn) < 0)
    return -1;

  return 0;
}
