/* connection.c
 *
 * SSH connection conforming to RFC 4253 sections 4-6
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ssh/connection.h"

#include "common/error.h"
#include "common/alloc.h"
#include "common/debug.h"
#include "common/network.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"
#include "ssh/banner.h"
#include "ssh/kex.h"

const char ssh_client_banner_string[] = "SSH-2.0-eessh_0.1\r\n";

struct SSH_CONN {
  int sock;
  struct SSH_HOST_BANNER server_banner;
  struct SSH_STRING session_id;
  struct SSH_STREAM in_stream;
  struct SSH_STREAM out_stream;
  struct SSH_BUF_READER last_pack_read;
};

static struct SSH_CONN *conn_new(void)
{
  struct SSH_CONN *conn = ssh_alloc(sizeof(struct SSH_CONN));
  if (conn == NULL) {
    ssh_set_error("out of memory");
    return NULL;
  }
  memset(&conn->server_banner, 0, sizeof(conn->server_banner));
  conn->session_id = ssh_str_new_empty();
  ssh_stream_init(&conn->in_stream);
  ssh_stream_init(&conn->out_stream);

  return conn;
}

void ssh_conn_close(struct SSH_CONN *conn)
{
  ssh_stream_close(&conn->in_stream);
  ssh_stream_close(&conn->out_stream);
  ssh_str_free(&conn->session_id);
  close(conn->sock);
  ssh_free(conn);
}

struct SSH_HOST_BANNER *ssh_conn_get_server_banner(struct SSH_CONN *conn)
{
  return &conn->server_banner;
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

/*
 * transport
 */

int ssh_conn_send_ignore_msg(struct SSH_CONN *conn)
{
  struct SSH_BUFFER *pack;
  
  pack = ssh_conn_new_packet(conn);
  if (pack == NULL)
    return -1;

  if (ssh_buf_write_u8(pack, SSH_MSG_IGNORE) < 0
      || ssh_buf_write_cstring(pack, "x"))
    return -1;
  
  if (ssh_conn_send_packet(conn) < 0)
    return -1;

  return 0;
}

struct SSH_CONN *ssh_conn_open(const char *server, const char *port)
{
  int sock;
  struct SSH_HOST_BANNER banner;
  struct SSH_CONN *conn;
  
  ssh_log("* connecting to server %s port %s\n", server, port);
  sock = ssh_net_connect(server, port);
  if (sock < 0)
    return NULL;

  if (ssh_net_write_all(sock, ssh_client_banner_string, sizeof(ssh_client_banner_string)-1) < 0) {
    close(sock);
    return NULL;
  }

  if (ssh_banner_read(&banner, sock) < 0) {
    close(sock);
    return NULL;
  }
  
  ssh_log("* got server version '%.*s'\n", (int) banner.version.len, banner.version.str);
  ssh_log("* got server software '%.*s'\n", (int) banner.software.len, banner.software.str);
  ssh_log("* got server comments '%.*s'\n", (int) banner.comments.len, banner.comments.str);

  if (! ((   banner.version.len == 4 && memcmp(banner.version.str, "1.99", banner.version.len) == 0)
	 || (banner.version.len == 3 && memcmp(banner.version.str,  "2.0", banner.version.len) == 0))) {
    close(sock);
    ssh_set_error("bad server version: '%.*s'", (int) banner.version.len, banner.version.str);
    return NULL;
  }

  conn = conn_new();
  if (conn == NULL) {
    close(sock);
    return NULL;
  }
  conn->sock = sock;
  conn->server_banner = banner;

  if (ssh_conn_send_ignore_msg(conn) < 0) {
    ssh_conn_close(conn);
    return NULL;
  }

  if (ssh_conn_send_ignore_msg(conn) < 0) {
    ssh_conn_close(conn);
    return NULL;
  }

  if (ssh_kex_run(conn) < 0) {
    ssh_conn_close(conn);
    return NULL;
  }

#if 0
  {
    struct SSH_BUF_READER *pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return NULL;
    }
    dump_packet_reader("received packet", pack, conn->in_stream.mac_len);
  }
#endif

#if 1
  // send SSH_MSG_IGNORE packet
  {
    struct SSH_BUFFER *pack;

    ssh_log("* making new packet\n");
    pack = ssh_conn_new_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return NULL;
    }

    //if (ssh_buf_write_u8(pack, SSH_MSG_SERVICE_REQUEST) < 0
    if (ssh_buf_write_u8(pack, SSH_MSG_IGNORE) < 0
	|| ssh_buf_write_cstring(pack, "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ") < 0) {
      ssh_conn_close(conn);
      return NULL;
    }
    
    ssh_log("* sending packet\n");
    if (ssh_conn_send_packet(conn) < 0) {
      ssh_conn_close(conn);
      return NULL;
    }
    ssh_log("* packet sent\n");
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
      return NULL;
    }

    ssh_log("* writing packet type\n");
    if (ssh_buf_write_u8(pack, SSH_MSG_SERVICE_REQUEST) < 0
	|| ssh_buf_write_cstring(pack, "ssh-userauth") < 0) {
	//|| ssh_buf_write_cstring(pack, "ssh-connection")) {
      ssh_conn_close(conn);
      return NULL;
    }
    
    ssh_log("* sending packet\n");
    if (ssh_conn_send_packet(conn) < 0) {
      ssh_conn_close(conn);
      return NULL;
    }
    ssh_log("* packet sent\n");
  }
#endif

  {
    struct SSH_BUF_READER *pack = ssh_conn_recv_packet(conn);
    if (pack == NULL) {
      ssh_conn_close(conn);
      return NULL;
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
      return NULL;
    }

    ssh_log("* writing packet type SSH_MSG_USERAUTH_REQUEST\n");
    if (ssh_buf_write_u8(pack, SSH_MSG_USERAUTH_REQUEST) < 0
        || ssh_buf_write_cstring(pack, "massaro") < 0
	|| ssh_buf_write_cstring(pack, "ssh-connection") < 0
	|| ssh_buf_write_cstring(pack, "password") < 0
	|| ssh_buf_write_u8(pack, 0) < 0
	|| ssh_buf_write_cstring(pack, "123qwe") < 0) {
      ssh_conn_close(conn);
      return NULL;
    }
    
    ssh_log("* sending packet\n");
    if (ssh_conn_send_packet(conn) < 0) {
      ssh_conn_close(conn);
      return NULL;
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
      return NULL;
    }

    dump_packet_reader("received packet", pack, conn->in_stream.mac_len);
  }
#endif
  
  return conn;
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
