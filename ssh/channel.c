/* channel.c */

#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "ssh/channel_i.h"

#include "common/network_i.h"
#include "ssh/connection_i.h"
#include "ssh/channel_session_i.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/alloc.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"

typedef int (*chan_type_fn_opened)(struct SSH_CHAN *chan);
typedef int (*chan_type_fn_process_packet)(struct SSH_CHAN *chan, struct SSH_BUF_READER *pack);

static const struct CHAN_TYPE_INFO {
  enum SSH_CHAN_TYPE type;
  const char *name;
  chan_type_fn_opened opened;
  chan_type_fn_process_packet process_packet;
} chan_type_table[] = {
  { SSH_CHAN_TYPE_SESSION, "session", ssh_chan_session_opened, ssh_chan_session_process_packet },
};

static const struct CHAN_TYPE_INFO *chan_get_type_info(enum SSH_CHAN_TYPE type)
{
  int i;

  for (i = 0; i < sizeof(chan_type_table)/sizeof(chan_type_table[0]); i++)
    if (chan_type_table[i].type == type)
      return &chan_type_table[i];
  ssh_set_error("unknown channel type %d", type);
  return NULL;
}

static short chan_flags_to_pollfd_events(int chan_fd_flags)
{
  short events = 0;
  if ((chan_fd_flags & (SSH_CHAN_FD_READ|SSH_CHAN_FD_CLOSE)) != 0)
    events |= POLLIN | POLLHUP;
  if ((chan_fd_flags & SSH_CHAN_FD_WRITE) != 0)
    events |= POLLOUT;
  return events;
}

static int pollfd_events_to_chan_flags(short pollfd_events)
{
  int flags = 0;
  
  if ((pollfd_events & (POLLIN|POLLPRI)) != 0)
    flags |= SSH_CHAN_FD_READ;
  if ((pollfd_events & POLLHUP) != 0)
    flags |= SSH_CHAN_FD_CLOSE;
  if ((pollfd_events & (POLLOUT|POLLWRBAND)) != 0)
    flags |= SSH_CHAN_FD_WRITE;
  return flags;
}

static int update_poll_fd_events(struct pollfd *poll_fds, nfds_t *num_poll_fds, int fd, short add_events, short remove_events)
{
  int i;
  
  for (i = 0; i < *num_poll_fds; i++) {
    if (poll_fds[i].fd == fd) {
      poll_fds[i].events |= add_events;
      poll_fds[i].events &= ~remove_events;
      return 0;
    }
  }
  if (*num_poll_fds < MAX_POLL_FDS) {
    poll_fds[*num_poll_fds].fd = fd;
    poll_fds[*num_poll_fds].events = add_events & ~remove_events;
    (*num_poll_fds)++;
    return 0;
  }
  ssh_set_error("too many fds to watch");
  return -1;
}

static struct SSH_CHAN *chan_new(struct SSH_CONN *conn, const struct SSH_CHAN_CONFIG *cfg)
{
  struct SSH_CHAN *chan;
  uint32_t local_num;
  int i;

  // allocate local number
  local_num = 0;
  for (i = 0; i < conn->num_channels; i++) {
    if (conn->channels[i]->local_num == local_num) {
      local_num++;
      i = 0;
    }
  }
  
  if ((chan = ssh_alloc(sizeof(struct SSH_CHAN))) == NULL)
    return NULL;
  chan->conn = conn;
  chan->userdata = cfg->userdata;
  chan->status = SSH_CHAN_STATUS_REQUESTED;
  chan->num_watch_fds = 0;
  
  chan->local_num = local_num;
  chan->remote_num = 0;
  chan->local_max_packet_size = 65536;
  chan->local_window_size = 256*1024;
  chan->remote_max_packet_size = 0;
  chan->remote_window_size = 0;

  chan->type = cfg->type;
  chan->type_config = cfg->type_config;
  chan->notify_open = cfg->notify_open;
  chan->notify_open_failed = cfg->notify_open_failed;
  chan->notify_closed = cfg->notify_closed;
  chan->notify_fd_ready = cfg->notify_fd_ready;
  chan->notify_received = cfg->notify_received;
  chan->notify_received_ext = cfg->notify_received_ext;
  
  conn->channels[conn->num_channels++] = chan;
  return chan;
}

void ssh_chan_free(struct SSH_CHAN *chan)
{
  ssh_free(chan);
}

static struct SSH_CHAN *chan_get_by_num(struct SSH_CONN *conn, uint32_t local_num)
{
  int i;

  for (i = 0; i < conn->num_channels; i++)
    if (conn->channels[i]->local_num == local_num)
      return conn->channels[i];
  ssh_set_error("unknown channel number '%u'\n", local_num);
  return NULL;
}

static void chan_remove_closed_channels(struct SSH_CONN *conn)
{
  int i;

  for (i = 0; i < conn->num_channels; ) {
    if (conn->channels[i]->status == SSH_CHAN_STATUS_CLOSED) {
      struct SSH_CHAN *free_chan = conn->channels[i];
      memmove(&conn->channels[i], &conn->channels[i+1], (conn->num_channels-i-1) * sizeof(struct SSH_CHANNEL *));
      conn->num_channels--;
      ssh_chan_free(free_chan);
    } else
      i++;
  }
}

static int chan_handle_global_request(struct SSH_CONN *conn, struct SSH_BUF_READER *pack)
{
  struct SSH_STRING req_name;
  uint8_t want_reply;

  if (ssh_buf_read_skip(pack, 1) < 0  // packet type
      || ssh_buf_read_string(pack, &req_name) < 0
      || ssh_buf_read_u8(pack, &want_reply) < 0)
    return -1;

  ssh_log("* received global request '%.*s' (want_reply=%d)\n", (int) req_name.len, req_name.str, want_reply);
  if (want_reply) {
    struct SSH_BUFFER *reply = ssh_conn_new_packet(conn);
    if (reply == NULL
        || ssh_buf_write_u8(reply, SSH_MSG_REQUEST_FAILURE) < 0
        || ssh_conn_send_packet(conn) < 0)
      return -1;
  }
  return 0;
}

static int chan_send_channel_open(struct SSH_CONN *conn, struct SSH_CHAN *chan)
{
  struct SSH_BUFFER *pack;
  const struct CHAN_TYPE_INFO *type_info = chan_get_type_info(chan->type);

  if (type_info == NULL
      || (pack = ssh_conn_new_packet(conn)) == NULL
      || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_OPEN) < 0
      || ssh_buf_write_cstring(pack, type_info->name) < 0
      || ssh_buf_write_u32(pack, chan->local_num) < 0
      || ssh_buf_write_u32(pack, chan->local_window_size) < 0
      || ssh_buf_write_u32(pack, chan->local_max_packet_size) < 0
      || ssh_conn_send_packet(conn) < 0)
    return -1;
  return 0;
}

static int chan_check_adjust_local_window(struct SSH_CONN *conn, struct SSH_CHAN *chan, size_t len)
{
  uint32_t consume_len;

  if (len > 0xffffffffu) {
    ssh_log("WARNING: size too large in chan_check_adjust_window()");
    consume_len = 0xffffffffu;
  } else {
    consume_len = (uint32_t) len;
  }

  if (chan->local_window_size < consume_len) {
    ssh_log("WARNING: received data exceeds window size\n");
    chan->local_window_size = 0;
  } else {
    chan->local_window_size -= consume_len;
  }

  if (chan->local_window_size < 512*1024) {
    struct SSH_BUFFER *pack;
    uint32_t bytes_to_add = 2*1024*1024 - chan->local_window_size;

    //ssh_log("* adjusting local window size: +%u bytes\n", bytes_to_add);
    if ((pack = ssh_conn_new_packet(conn)) == NULL
        || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_WINDOW_ADJUST) < 0
        || ssh_buf_write_u32(pack, chan->remote_num) < 0
        || ssh_buf_write_u32(pack, bytes_to_add) < 0
        || ssh_conn_send_packet(conn) < 0)
      return -1;
    chan->local_window_size += bytes_to_add;
  }
  return 0;
}

static int chan_process_channel_packet(struct SSH_CONN *conn, struct SSH_BUF_READER *pack)
{
  struct SSH_CHAN *chan;
  uint8_t pack_type;
  uint32_t local_num;
  
  if (ssh_buf_read_u8(pack, &pack_type) < 0
      || ssh_buf_read_u32(pack, &local_num) < 0
      || (chan = chan_get_by_num(conn, local_num)) == NULL)
    return -1;

  switch (pack_type) {
  case SSH_MSG_CHANNEL_WINDOW_ADJUST:
    {
      uint32_t bytes_to_add;
      
      if (ssh_buf_read_u32(pack, &bytes_to_add) < 0)
        return 1;
      //ssh_log("* adjusting remote window size: +%u bytes\n", bytes_to_add);
      if (chan->remote_window_size + bytes_to_add < chan->remote_window_size) {
        ssh_log("remote window size overflow: %u + %u\n", chan->remote_window_size, bytes_to_add);
        chan->remote_window_size = 0xffffffffu;
      } else {
        chan->remote_window_size += bytes_to_add;
      }
    }
    break;

  case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
    {
      const struct CHAN_TYPE_INFO *type_info = chan_get_type_info(chan->type);
      if (type_info == NULL)
        return -1;
      
      if (ssh_buf_read_u32(pack, &chan->remote_num) < 0
          || ssh_buf_read_u32(pack, &chan->remote_window_size) < 0
          || ssh_buf_read_u32(pack, &chan->remote_max_packet_size) < 0)
        return -1;

      if (type_info->opened(chan) < 0)
        return -1;
    }
    break;
    
  case SSH_MSG_CHANNEL_OPEN_FAILURE:
    chan->notify_open_failed(chan, chan->userdata);
    ssh_chan_close(chan);
    break;

  case SSH_MSG_CHANNEL_DATA:
    {
      struct SSH_STRING data;
      if (ssh_buf_read_string(pack, &data) < 0)
        return -1;
      chan->notify_received(chan, chan->userdata, data.str, data.len);
      if (chan_check_adjust_local_window(conn, chan, data.len) < 0)
        return -1;
    }
    break;

  case SSH_MSG_CHANNEL_EOF:
    chan->notify_received(chan, chan->userdata, NULL, 0);
    break;

  case SSH_MSG_CHANNEL_CLOSE:
    ssh_chan_close(chan);
    break;

  default:
    {
      const struct CHAN_TYPE_INFO *type_info = chan_get_type_info(chan->type);
      if (type_info == NULL
          || type_info->process_packet(chan, pack) < 0)
        return -1;
    }
    break;
  }

  return 0;
}

static int chan_process_packets(struct SSH_CONN *conn)
{
  uint8_t pack_type;
  
  while (1) {
    struct SSH_BUF_READER *pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      if (errno == EWOULDBLOCK)
        return 0;
      return -1;
    }

    pack_type = ssh_packet_get_type(pack);

    // channel packet
    if (pack_type >= 90 && pack_type <= 127) {
      if (chan_process_channel_packet(conn, pack) < 0)
        return -1;
      continue;
    }

    // other packet types
    switch (pack_type) {
    case SSH_MSG_GLOBAL_REQUEST:
      if (chan_handle_global_request(conn, pack) < 0)
        return -1;
      break;

    case SSH_MSG_IGNORE:
    case SSH_MSG_UNIMPLEMENTED:
    case SSH_MSG_DEBUG:
      break;

    default:
      dump_packet_reader("received unknown packet", pack, conn->in_stream.mac_len);
      break;
    }
  }
}

static void chan_notify_channels_watch_fds(struct SSH_CONN *conn, struct pollfd *poll_fd)
{
  int i, j;

  for (i = 0; i < conn->num_channels; i++) {
    struct SSH_CHAN *chan = conn->channels[i];
    for (j = 0; j < chan->num_watch_fds; j++) {
      if (poll_fd->revents != 0 && poll_fd->fd == chan->watch_fds[j].fd) {
        chan->notify_fd_ready(chan, chan->userdata, poll_fd->fd,
                              pollfd_events_to_chan_flags(poll_fd->revents));
      }
    }
  }
}

static void chan_collect_channel_poll_fds(struct SSH_CHAN *chan, struct pollfd *ret_poll_fds, nfds_t *ret_num_poll_fds)
{
  int i;
  
  for (i = 0; i < chan->num_watch_fds; i++) {
    struct pollfd *chan_fd = &chan->watch_fds[i];
    update_poll_fd_events(ret_poll_fds, ret_num_poll_fds, chan_fd->fd, chan_fd->events, 0);
  }
}

static int chan_loop(struct SSH_CONN *conn)
{
  struct pollfd poll_fds[MAX_POLL_FDS];
  nfds_t num_poll_fds;
  int i;

  while (1) {
    chan_remove_closed_channels(conn);
    if (conn->num_channels == 0)
      break;
    
    poll_fds[0].fd = conn->sock;
    poll_fds[0].events = POLLIN;
    if (ssh_conn_send_is_pending(conn))
      poll_fds[0].events |= POLLOUT;
    num_poll_fds = 1;

    for (i = 0; i < conn->num_channels; i++)
      chan_collect_channel_poll_fds(conn->channels[i], poll_fds, &num_poll_fds);

    //ssh_log("* polling %d fds\n", (int) num_poll_fds); for (i = 0; i < num_poll_fds; i++) ssh_log(" -> fd %d with flags %d\n", poll_fds[i].fd, poll_fds[i].events);
    if (poll(poll_fds, num_poll_fds, -1) < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    //ssh_log("* got poll result:\n"); for (i = 0; i < num_poll_fds; i++) ssh_log(" -> fd %d has flags %d\n", poll_fds[i].fd, poll_fds[i].revents);

    if ((poll_fds[0].revents & POLLIN) != 0) {
      if (chan_process_packets(conn) < 0)
        return -1;
    }
    if ((poll_fds[0].revents & POLLOUT) != 0) {
      if (ssh_conn_send_flush(conn) < 0 && errno != EWOULDBLOCK)
        return -1;
    }

    for (i = 1; i < num_poll_fds; i++)
      chan_notify_channels_watch_fds(conn, &poll_fds[i]);
  }

  return 0;
}

static void chan_close_all_channels(struct SSH_CONN *conn)
{
  int i;
  
  for (i = 0; i < conn->num_channels; i++)
    ssh_chan_close(conn->channels[i]);
  chan_remove_closed_channels(conn);
}

int ssh_chan_run_connection(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs)
{
  int i;

  if (ssh_net_set_sock_blocking(conn->sock, 0) < 0)
    return -1;
  
  for (i = 0; i < num_channels; i++) {
    struct SSH_CHAN *chan = chan_new(conn, &channel_cfgs[i]);
    if (chan == NULL)
      return -1;
    if (chan_send_channel_open(conn, chan) < 0)
      return -1;
    chan->status = SSH_CHAN_STATUS_REQUESTED;
  }
  
  if (chan_loop(conn) < 0) {
    chan_close_all_channels(conn);
    return -1;
  }

  chan_close_all_channels(conn);
  return 0;
}

/* ------- client API ------------------------- */

uint32_t ssh_chan_get_num(struct SSH_CHAN  *chan)
{
  return chan->local_num;
}

ssize_t ssh_chan_send_data(struct SSH_CHAN *chan, void *data, size_t data_len)
{
  struct SSH_BUFFER *pack;
  size_t process_len = data_len;

  if (process_len > chan->remote_window_size)
    process_len = chan->remote_window_size;
  if (process_len > chan->remote_max_packet_size)
    process_len = chan->remote_max_packet_size;
  if (process_len > SSIZE_MAX)
    process_len = SSIZE_MAX;

  if (process_len == 0)
    return 0;
  
  if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
      || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_DATA) < 0
      || ssh_buf_write_u32(pack, chan->remote_num) < 0
      || ssh_buf_write_data(pack, data, process_len) < 0
      || ssh_conn_send_packet(chan->conn) < 0)
    return -1;

  chan->remote_window_size -= process_len;
  return process_len;
}

ssize_t ssh_chan_send_ext_data(struct SSH_CHAN *chan, uint32_t data_type_code, void *data, size_t data_len)
{
  struct SSH_BUFFER *pack;
  size_t process_len = data_len;

  if (process_len > chan->remote_window_size)
    process_len = chan->remote_window_size;
  if (process_len > chan->remote_max_packet_size)
    process_len = chan->remote_max_packet_size;
  if (process_len > SSIZE_MAX)
    process_len = SSIZE_MAX;

  if (process_len == 0)
    return 0;
  
  if ((pack = ssh_conn_new_packet(chan->conn)) == NULL
      || ssh_buf_write_u8(pack, SSH_MSG_CHANNEL_EXTENDED_DATA) < 0
      || ssh_buf_write_u32(pack, chan->remote_num) < 0
      || ssh_buf_write_u32(pack, data_type_code) < 0
      || ssh_buf_write_data(pack, data, process_len) < 0
      || ssh_conn_send_packet(chan->conn) < 0)
    return -1;

  chan->remote_window_size -= process_len;
  return process_len;
}

int ssh_chan_watch_fd(struct SSH_CHAN  *chan, int fd, uint8_t enable_fd_flags, uint8_t disable_fd_flags)
{
  short enable_events = chan_flags_to_pollfd_events(enable_fd_flags);
  short disable_events = chan_flags_to_pollfd_events(disable_fd_flags);
  int i;

  //ssh_log("watch fd %d with events (%d,%d)\n", fd, enable_fd_flags, disable_fd_flags);
  
  if (update_poll_fd_events(chan->watch_fds, &chan->num_watch_fds, fd, enable_events, disable_events) < 0) {
    if (enable_events != 0) // no error if there's no space to add only disable_events
      return -1;
  }

  // remove empty watches
  for (i = 0; i < chan->num_watch_fds; ) {
    if (chan->watch_fds[i].events == 0) {
      memmove(&chan->watch_fds[i], &chan->watch_fds[i+1], (chan->num_watch_fds-i-1) * sizeof(struct pollfd));
      chan->num_watch_fds--;
    } else
      i++;
  }

  return 0;
}

void ssh_chan_close(struct SSH_CHAN  *chan)
{
  if (chan->status == SSH_CHAN_STATUS_OPEN) {
    chan->notify_closed(chan, chan->userdata);
    chan->status = SSH_CHAN_STATUS_CLOSED;
  }
}
