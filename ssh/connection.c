/* connection.c
 *
 * SSH connection conforming to RFC 4253 sections 4-6
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ssh/connection.h"

#include "common/error.h"
#include "common/alloc.h"
#include "common/debug.h"
#include "common/network.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"
#include "ssh/version_string.h"
#include "ssh/kex.h"

#define CLIENT_SOFTWARE "eessh_0.1"

struct SSH_CONN {
  int sock;
  struct SSH_STRING server_hostname;
  struct SSH_VERSION_STRING client_version_string;
  struct SSH_VERSION_STRING server_version_string;
  struct SSH_STRING session_id;
  struct SSH_STREAM in_stream;
  struct SSH_STREAM out_stream;
  struct SSH_BUF_READER last_pack_read;
  ssh_host_identity_checker host_identity_checker;
};

struct SSH_CONN *ssh_conn_new(void)
{
  struct SSH_CONN *conn = ssh_alloc(sizeof(struct SSH_CONN));
  if (conn == NULL)
    return NULL;
  conn->sock = -1;
  conn->client_version_string.len = 0;
  conn->server_version_string.len = 0;
  conn->server_hostname = ssh_str_new_empty();
  conn->session_id = ssh_str_new_empty();
  ssh_stream_init(&conn->in_stream);
  ssh_stream_init(&conn->out_stream);
  conn->host_identity_checker = NULL;
  return conn;
}

void ssh_conn_close(struct SSH_CONN *conn)
{
  if (conn->sock >= 0) {
    close(conn->sock);
    conn->sock = -1;
  }
}

void ssh_conn_free(struct SSH_CONN *conn)
{
  ssh_stream_close(&conn->in_stream);
  ssh_stream_close(&conn->out_stream);
  ssh_str_free(&conn->session_id);
  ssh_str_free(&conn->server_hostname);
  ssh_free(conn);
}

int ssh_conn_set_client_software(struct SSH_CONN *conn, const char *software, const char *comments)
{
  if (ssh_version_string_build(&conn->client_version_string, software, comments) < 0) {
    conn->client_version_string.len = 0;
    return -1;
  }
  return 0;
}

struct SSH_VERSION_STRING *ssh_conn_get_client_version_string(struct SSH_CONN *conn)
{
  return &conn->client_version_string;
}

struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn)
{
  return &conn->server_version_string;
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

void ssh_conn_set_host_key_checker(struct SSH_CONN *conn, ssh_host_identity_checker checker)
{
  conn->host_identity_checker = checker;
}

int ssh_conn_check_server_identity(struct SSH_CONN *conn, struct SSH_STRING *server_host_key)
{
  if (conn->host_identity_checker != NULL)
    return conn->host_identity_checker((char *) conn->server_hostname.str, server_host_key);

  ssh_set_error("no server identity checker set");
  return -1;
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

int conn_setup(struct SSH_CONN *conn)
{
  struct SSH_VERSION_STRING *server_version;
  
  if (conn->client_version_string.len == 0)
    if (ssh_conn_set_client_software(conn, CLIENT_SOFTWARE, "--") < 0) {
      ssh_set_error("internal error: can't set default software version");
      return -1;
    }
  
  if (ssh_net_write_all(conn->sock, conn->client_version_string.buf, conn->client_version_string.len) < 0
      || ssh_net_write_all(conn->sock, "\r\n", 2) < 0)
    return -1;

  server_version = &conn->server_version_string;
  if (ssh_version_string_read(server_version, conn->sock, &conn->in_stream.net_buffer) < 0)
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
  if (ssh_str_alloc(&conn->server_hostname, strlen(server) + strlen(port) + 2) < 0)
    return -1;
  snprintf((char *) conn->server_hostname.str, conn->server_hostname.len, "%s,%s", server, port);
  return 0;
}

int ssh_conn_open(struct SSH_CONN *conn, const char *server, const char *port)
{
  if (conn_save_hostname(conn, server, port) < 0)
    return -1;
  
  ssh_log("* connecting to server %s port %s\n", server, port);
  conn->sock = ssh_net_connect(server, port);
  if (conn->sock < 0
      || conn_setup(conn) < 0) {
    ssh_conn_close(conn);
    return -1;
  }

  if (ssh_kex_run(conn) < 0) {
    ssh_conn_close(conn);
    return -1;
  }

#if 0
  {
    struct SSH_BUF_READER *pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return -1;
    }
    dump_packet_reader("received packet", pack, conn->in_stream.mac_len);
  }
#endif

#if 1
  if (ssh_conn_send_ignore_msg(conn, "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ") < 0) {
    ssh_conn_close(conn);
    return -1;
  }
#endif
  
#if 1
  ssh_log("* sending SSH_MSG_SERVICE_REQUEST...\n");

  // send SSH_MSG_SERVICE_REQUEST packet
  {
    struct SSH_BUFFER *pack;

    ssh_log("* making new packet\n");
    pack = ssh_conn_new_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return -1;
    }

    ssh_log("* writing packet type\n");
    if (ssh_buf_write_u8(pack, SSH_MSG_SERVICE_REQUEST) < 0
        || ssh_buf_write_cstring(pack, "ssh-userauth") < 0) {
        //|| ssh_buf_write_cstring(pack, "ssh-connection")) {
      ssh_conn_close(conn);
      return -1;
    }
    
    ssh_log("* sending packet\n");
    if (ssh_conn_send_packet(conn) < 0) {
      ssh_conn_close(conn);
      return -1;
    }
    ssh_log("* packet sent\n");
  }
#endif

  {
    struct SSH_BUF_READER *pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return -1;
    }
    dump_packet_reader("received packet", pack, conn->in_stream.mac_len);
  }

#if 1
  // send SSH_MSG_USERAUTH_REQUEST packet
  {
    struct SSH_BUFFER *pack;

    ssh_log("* making new packet\n");
    pack = ssh_conn_new_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return -1;
    }

    ssh_log("* writing packet type SSH_MSG_USERAUTH_REQUEST\n");
    if (ssh_buf_write_u8(pack, SSH_MSG_USERAUTH_REQUEST) < 0
        || ssh_buf_write_cstring(pack, "massaro") < 0
        || ssh_buf_write_cstring(pack, "ssh-connection") < 0
        || ssh_buf_write_cstring(pack, "password") < 0
        || ssh_buf_write_u8(pack, 0) < 0
        || ssh_buf_write_cstring(pack, "123qwe") < 0) {
      ssh_conn_close(conn);
      return -1;
    }
    
    ssh_log("* sending packet\n");
    if (ssh_conn_send_packet(conn) < 0) {
      ssh_conn_close(conn);
      return -1;
    }
    ssh_log("* packet sent\n");
  }
#endif
  
#if 1
  for (int i = 0; i < 2; i++) {
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

struct SSH_BUFFER *ssh_conn_new_packet(struct SSH_CONN *conn)
{
  return ssh_stream_new_packet(&conn->out_stream);
}

int ssh_conn_send_packet(struct SSH_CONN *conn)
{
  return ssh_stream_send_packet(&conn->out_stream, conn->sock);
}

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
    uint8_t type;
    struct SSH_BUF_READER *pack;

    pack = ssh_conn_recv_packet(conn);
    if (pack == NULL)
      return NULL;

    type = ssh_packet_get_type(pack);
    if (type != SSH_MSG_IGNORE
        && type != SSH_MSG_UNIMPLEMENTED
        && type != SSH_MSG_DEBUG)
      return pack;
  }
}
