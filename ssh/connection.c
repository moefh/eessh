/* connection.c
 *
 * SSH connection conforming to RFC 4253 sections 4-6
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ssh/connection_i.h"

#include "common/network_i.h"
#include "ssh/version_string_i.h"
#include "ssh/kex_i.h"
#include "ssh/userauth_i.h"
#include "ssh/channel_i.h"

#include "common/error.h"
#include "common/alloc.h"
#include "common/debug.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"

#if !DEBUG_CONN
#include "common/disable_debug_i.h"
#endif

#define CLIENT_SOFTWARE "eessh_0.1"

static struct SSH_CONN *conn_new(void)
{
  struct SSH_CONN *conn = ssh_alloc(sizeof(struct SSH_CONN));
  if (conn == NULL)
    return NULL;
  conn->sock = -1;
  conn->client_version_string.len = 0;
  conn->server_version_string.len = 0;
  conn->server_hostname = ssh_str_new_empty();
  conn->session_id = ssh_str_new_empty();
  ssh_stream_init(&conn->in_stream, SSH_STREAM_TYPE_READ);
  ssh_stream_init(&conn->out_stream, SSH_STREAM_TYPE_WRITE);

  conn->num_channels = 0;
  
  conn->server_identity_checker = NULL;

  conn->username = ssh_str_new_empty();
  conn->password_reader = NULL;
  return conn;
}

static void conn_free(struct SSH_CONN *conn)
{
  int i;

  for (i = 0; i < conn->num_channels; i++)
    ssh_chan_free(conn->channels[i]);

  ssh_stream_close(&conn->in_stream);
  ssh_stream_close(&conn->out_stream);
  ssh_str_free(&conn->session_id);
  ssh_str_free(&conn->server_hostname);
  ssh_str_free(&conn->username);
  ssh_free(conn);
}

void ssh_conn_close(struct SSH_CONN *conn)
{
  int i;
  
  for (i = 0; i < conn->num_channels; i++)
    ssh_chan_close(conn->channels[i]);
  close(conn->sock);
  conn_free(conn);
}

struct SSH_VERSION_STRING *ssh_conn_get_client_version_string(struct SSH_CONN *conn)
{
  return &conn->client_version_string;
}

struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn)
{
  return &conn->server_version_string;
}

struct SSH_STRING ssh_conn_get_server_hostname(struct SSH_CONN *conn)
{
  return conn->server_hostname;
}

int ssh_conn_set_cipher(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_CIPHER_TYPE type, struct SSH_STRING *iv, struct SSH_STRING *key)
{
  struct SSH_STREAM *stream = (dir == SSH_CONN_CTS) ? &conn->out_stream : &conn->in_stream;
  enum SSH_CIPHER_DIRECTION cipher_dir = (dir == SSH_CONN_CTS) ? SSH_CIPHER_ENCRYPT : SSH_CIPHER_DECRYPT;
  
  return ssh_stream_set_cipher(stream, type, cipher_dir, iv, key);
}

int ssh_conn_set_mac(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_MAC_TYPE type, struct SSH_STRING *key)
{
  struct SSH_STREAM *stream = (dir == SSH_CONN_CTS) ? &conn->out_stream : &conn->in_stream;
  
  return ssh_stream_set_mac(stream, type, key);
}

void ssh_conn_set_session_id(struct SSH_CONN *conn, struct SSH_STRING *session_id)
{
  conn->session_id = *session_id;
  *session_id = ssh_str_new_empty();
}

struct SSH_STRING *ssh_conn_get_session_id(struct SSH_CONN *conn)
{
  return &conn->session_id;
}

int ssh_conn_check_server_identity(struct SSH_CONN *conn, struct SSH_STRING *server_host_key)
{
  if (conn->server_identity_checker != NULL)
    return conn->server_identity_checker((char *) conn->server_hostname.str, server_host_key);

  ssh_set_error("no server identity checker set");
  return -1;
}

struct SSH_STRING ssh_conn_get_username(struct SSH_CONN *conn)
{
  return conn->username;
}

ssh_conn_password_reader ssh_conn_get_password_reader(struct SSH_CONN *conn)
{
  return conn->password_reader;
}

/*
 * transport
 */

int ssh_conn_send_ignore_msg(struct SSH_CONN *conn, const char *msg)
{
  struct SSH_BUFFER *pack;
  
  pack = ssh_conn_new_packet(conn);
  if (pack == NULL)
    return -1;

  if (ssh_buf_write_u8(pack, SSH_MSG_IGNORE) < 0
      || ssh_buf_write_cstring(pack, msg))
    return -1;
  
  if (ssh_conn_send_packet(conn) < 0)
    return -1;

  return 0;
}

static int conn_setup(struct SSH_CONN *conn)
{
  struct SSH_VERSION_STRING *server_version;

  if (ssh_net_write(conn->sock, conn->client_version_string.buf, conn->client_version_string.len) < 0
      || ssh_net_write(conn->sock, "\r\n", 2) < 0)
    return -1;

  server_version = &conn->server_version_string;
  if (ssh_version_string_read(server_version, conn->sock, &conn->in_stream.net.read.buf) < 0)
    return -1;
  
  ssh_log("* got server version '%.*s'\n", (int) server_version->version.len, server_version->version.str);
  ssh_log("* got server software '%.*s'\n", (int) server_version->software.len, server_version->software.str);
  ssh_log("* got server comments '%.*s'\n", (int) server_version->comments.len, server_version->comments.str);

  if (! ((   server_version->version.len == 4 && memcmp(server_version->version.str, "1.99", server_version->version.len) == 0)
         || (server_version->version.len == 3 && memcmp(server_version->version.str,  "2.0", server_version->version.len) == 0))) {
    ssh_set_error("bad server version: '%.*s'", (int) server_version->version.len, server_version->version.str);
    return -1;
  }

  return 0;
}

static int conn_save_hostname(struct SSH_CONN *conn, const char *server, const char *port)
{
  if (port == NULL)
    port = "22";
  if (ssh_str_alloc(&conn->server_hostname, strlen(server) + strlen(port) + 2) < 0)
    return -1;
  snprintf((char *) conn->server_hostname.str, conn->server_hostname.len, "%s,%s", server, port);
  return 0;
}

static int conn_set_client_software(struct SSH_CONN *conn, const char *software, const char *comments)
{
  if (ssh_version_string_build(&conn->client_version_string, software, comments) < 0) {
    conn->client_version_string.len = 0;
    return -1;
  }
  return 0;
}

static int conn_connect(struct SSH_CONN *conn, const struct SSH_CONN_CONFIG *cfg)
{
  const char *client_software, *client_comments, *port;

  if (cfg->server == NULL) {
    ssh_set_error("server must not be NULL");
    return -1;
  }
  if (cfg->username == NULL) {
    ssh_set_error("username must not be NULL");
    return -1;
  }
  
  if (conn_save_hostname(conn, cfg->server, cfg->port) < 0
      || ssh_str_dup_cstring(&conn->username, cfg->username) < 0)
    return -1;
  conn->password_reader = cfg->password_reader;
  conn->server_identity_checker = cfg->server_identity_checker;
  
  client_software = (cfg->version_software != NULL) ? cfg->version_software : CLIENT_SOFTWARE;
  client_comments = (cfg->version_comments != NULL) ? cfg->version_comments : "--";
  if (conn_set_client_software(conn, client_software, client_comments) < 0) {
    ssh_set_error("bad software version string");
    return -1;
  }

  port = (cfg->port != NULL) ? cfg->port : "22";
  ssh_log("* connecting to server %s port %s\n", cfg->server, port);
  
  conn->sock = ssh_net_connect(cfg->server, port);
  if (conn->sock < 0)
    return -1;

  if (conn_setup(conn) < 0
      || ssh_kex_run(conn) < 0
      || ssh_userauth_run(conn) < 0) {
    close(conn->sock);
    return -1;
  }

  return 0;
}

struct SSH_CONN *ssh_conn_open(const struct SSH_CONN_CONFIG *cfg)
{
  struct SSH_CONN *conn;

  if ((conn = conn_new()) == NULL)
    return NULL;

  if (conn_connect(conn, cfg) < 0) {
    conn_free(conn);
    return NULL;
  }
  return conn;
}

int ssh_conn_run(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs)
{
  return ssh_chan_run_connection(conn, num_channels, channel_cfgs);
}

struct SSH_BUFFER *ssh_conn_new_packet(struct SSH_CONN *conn)
{
  return ssh_stream_new_packet(&conn->out_stream);
}

int ssh_conn_send_packet(struct SSH_CONN *conn)
{
  return ssh_stream_send_packet(&conn->out_stream, conn->sock);
}

int ssh_conn_send_is_pending(struct SSH_CONN *conn)
{
  return ssh_stream_send_is_pending(&conn->out_stream);
}

int ssh_conn_send_flush(struct SSH_CONN *conn)
{
  return ssh_stream_send_flush(&conn->out_stream, conn->sock);
}

/*
 * Read packet.
 *
 * Will fail with errno=EWOULDBLOCK if sock is non-blocking and
 * there's no data to read, in which case it's OK to try again
 * later.
 */
struct SSH_BUF_READER *ssh_conn_recv_packet(struct SSH_CONN *conn)
{
  if (ssh_stream_recv_packet(&conn->in_stream, conn->sock) < 0)
    return NULL;
  conn->last_pack_read = ssh_buf_reader_new_from_buffer(&conn->in_stream.pack);
  ssh_buf_read_u32(&conn->last_pack_read, NULL);  // skip packet length
  ssh_buf_read_u8(&conn->last_pack_read, NULL);   // skip padding length
  return &conn->last_pack_read;
}

struct SSH_BUF_READER *ssh_conn_recv_packet_skip_ignore(struct SSH_CONN *conn)
{
  while (1) {
    uint32_t reason_code;
    struct SSH_BUF_READER *pack;

    if ((pack = ssh_conn_recv_packet(conn)) == NULL)
      return NULL;

    switch (ssh_packet_get_type(pack)) {
    case SSH_MSG_IGNORE:
    case SSH_MSG_UNIMPLEMENTED:
    case SSH_MSG_DEBUG:
      continue;

    case SSH_MSG_DISCONNECT:
      ssh_log("* RECEIVED SSH_MSG_DISCONNECT\n");
      if (ssh_buf_read_u32(pack, &reason_code) >= 0)
        ssh_set_error("server disconnect (%s)", ssh_const_get_disconnect_reason(reason_code));
      else
        ssh_set_error("server disconnect");
      return NULL;

    default:
      return pack;
    }    
  }
}
