/* userauth.c
 *
 * SSH user authentication conforming to RFC 4252
 *
 * TODO: handle SSH_MSG_USERAUTH_BANNER
 */

#include <stdlib.h>

#include "ssh/userauth.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/buffer.h"
#include "ssh/debug.h"
#include "ssh/ssh_constants.h"
#include "ssh/connection.h"

#define MAX_PASSWORD_TRIES 3

enum SSH_USERAUTH_RESULT {
  SSH_USERAUTH_RESULT_SUCCESS,
  SSH_USERAUTH_RESULT_PARTIAL_FAILURE,
  SSH_USERAUTH_RESULT_FAILURE,
};

static int userauth_init(struct SSH_CONN *conn)
{
  struct SSH_BUFFER *wpack;
  struct SSH_BUF_READER *rpack;
  struct SSH_STRING accept_service;
  
  if ((wpack = ssh_conn_new_packet(conn)) == NULL
      || ssh_buf_write_u8(wpack, SSH_MSG_SERVICE_REQUEST) < 0
      || ssh_buf_write_cstring(wpack, "ssh-userauth") < 0
      || ssh_conn_send_packet(conn) < 0) {
    return -1;
  }

  if ((rpack = ssh_conn_recv_packet_skip_ignore(conn)) == NULL)
    return -1;
  if (ssh_packet_get_type(rpack) != SSH_MSG_SERVICE_ACCEPT) {
    ssh_set_error("unexpected packet type: %d (expected SSH_MSG_SERVICE_ACCEPT=%d)", ssh_packet_get_type(rpack), SSH_MSG_SERVICE_ACCEPT);
    return -1;
  }
  if (ssh_buf_read_u8(rpack, NULL) < 0
      || ssh_buf_read_string(rpack, &accept_service) < 0
      || ssh_str_cmp_cstring(&accept_service, "ssh-userauth") != 0) {
    dump_packet_reader("ERROR PACKET:", rpack, 0);
    ssh_set_error("invalid SSH_MSG_SERVICE_ACCEPT response");
    return -1;
  }

  return 0;
}

static int userauth_read_response(struct SSH_CONN *conn, enum SSH_USERAUTH_RESULT *result)
{
  struct SSH_BUF_READER *pack;
  uint8_t pack_type;
  uint8_t partial_success;
  
  ssh_log("* reading userauth response\n");
  if ((pack = ssh_conn_recv_packet_skip_ignore(conn)) == NULL)
    return -1;

  pack_type = ssh_packet_get_type(pack);
  switch (pack_type) {
  case SSH_MSG_USERAUTH_SUCCESS:
    *result = SSH_USERAUTH_RESULT_SUCCESS;
    ssh_log("* userauth success\n");
    return 0;

  case SSH_MSG_USERAUTH_FAILURE:
    if (ssh_buf_read_u8(pack, &partial_success) < 0)
      return -1;
    *result = (partial_success) ? SSH_USERAUTH_RESULT_PARTIAL_FAILURE : SSH_USERAUTH_RESULT_FAILURE;
    return 0;

  default:
    ssh_set_error("unexpected packet of type %d (expected SSH_MSG_USERAUTH_SUCCESS or SSH_MSG_USERAUTH_FAILURE", pack_type);
    return -1;
  }
}

static int userauth_method_password(struct SSH_CONN *conn, enum SSH_USERAUTH_RESULT *result)
{
  struct SSH_BUFFER *pack;
  struct SSH_STRING server_hostname;
  struct SSH_STRING username;
  ssh_password_reader password_reader;
  char password[256];
  int num_tries;

  server_hostname = ssh_conn_get_server_hostname(conn);
  username = ssh_conn_get_username(conn);
  password_reader = ssh_conn_get_password_reader(conn);

  for (num_tries = 0; num_tries < MAX_PASSWORD_TRIES; num_tries++) {
    if (password_reader((char *) server_hostname.str, (char *) username.str, password, sizeof(password), num_tries != 0) < 0) {
      *result = SSH_USERAUTH_RESULT_FAILURE;
      return 0;
    }
    if ((pack = ssh_conn_new_packet(conn)) == NULL
        || ssh_buf_write_u8(pack, SSH_MSG_USERAUTH_REQUEST) < 0
        || ssh_buf_write_string(pack, &username) < 0
        || ssh_buf_write_cstring(pack, "ssh-connection") < 0
        || ssh_buf_write_cstring(pack, "password") < 0
        || ssh_buf_write_u8(pack, 0) < 0
        || ssh_buf_write_cstring(pack, password) < 0
        || ssh_conn_send_packet(conn) < 0
        || userauth_read_response(conn, result) < 0)
      return -1;

    if (*result == SSH_USERAUTH_RESULT_SUCCESS)
      return 0;
  }
  return 0;
}

static int userauth_method_none(struct SSH_CONN *conn, enum SSH_USERAUTH_RESULT *result)
{
  struct SSH_BUFFER *pack;
  struct SSH_STRING username;
  
  username = ssh_conn_get_username(conn);
  if ((pack = ssh_conn_new_packet(conn)) == NULL
      || ssh_buf_write_u8(pack, SSH_MSG_USERAUTH_REQUEST) < 0
      || ssh_buf_write_string(pack, &username) < 0
      || ssh_buf_write_cstring(pack, "ssh-connection") < 0
      || ssh_buf_write_cstring(pack, "none") < 0
      || ssh_conn_send_packet(conn) < 0)
    return -1;

  return userauth_read_response(conn, result);
}

int ssh_userauth_run(struct SSH_CONN *conn)
{
  enum SSH_USERAUTH_RESULT userauth_result;
  
  ssh_log("* starting user authentication\n");
  if (userauth_init(conn) < 0)
    return -1;

  if (ssh_conn_get_password_reader(conn) != NULL) {
    if (userauth_method_password(conn, &userauth_result) < 0)
      return -1;
    if (userauth_result == SSH_USERAUTH_RESULT_SUCCESS)
      return 0;
  }

  if (userauth_method_none(conn, &userauth_result) < 0)
    return -1;
  if (userauth_result == SSH_USERAUTH_RESULT_SUCCESS)
    return 0;

  ssh_log("* authentication failure\n");
  ssh_set_error("authentication failure");
  return -1;
}
