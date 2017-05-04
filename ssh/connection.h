/* connection.h */

#ifndef CONNECTION_H_FILE
#define CONNECTION_H_FILE

#include "common/buffer.h"
#include "ssh/stream.h"
#include "ssh/banner.h"
#include "crypto/algorithms.h"

#define ssh_packet_get_type(buf)  (((buf)->len < 6) ? -1 : (buf)->data[5])

struct SSH_CONN;

enum SSH_CONN_DIRECTION {
  SSH_CONN_CTS,
  SSH_CONN_STC,
};

struct SSH_CONN *ssh_conn_open(const char *server, const char *port);
void ssh_conn_close(struct SSH_CONN *conn);

struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn);
void ssh_conn_set_session_id(struct SSH_CONN *conn, struct SSH_STRING *session_id);
struct SSH_STRING *ssh_conn_get_session_id(struct SSH_CONN *conn);
struct SSH_STRING *ssh_conn_get_session_id(struct SSH_CONN *conn);
int ssh_conn_set_cipher(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_CIPHER_TYPE type, struct SSH_STRING *iv, struct SSH_STRING *key);
int ssh_conn_set_mac(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_MAC_TYPE type, struct SSH_STRING *key);

struct SSH_BUFFER *ssh_conn_new_packet(struct SSH_CONN *conn);
int ssh_conn_send_packet(struct SSH_CONN *conn);

struct SSH_BUF_READER *ssh_conn_recv_packet(struct SSH_CONN *conn);
struct SSH_BUF_READER *ssh_conn_recv_packet_skip_ignore(struct SSH_CONN *conn);

extern const char ssh_client_version_string[];

#endif /* CONNECTION_H_FILE */
