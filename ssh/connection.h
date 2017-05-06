/* connection.h */

#ifndef CONNECTION_H_FILE
#define CONNECTION_H_FILE

#include "common/buffer.h"
#include "ssh/stream.h"
#include "ssh/version_string.h"
#include "crypto/algorithms.h"

#define ssh_packet_get_type(buf)  (((buf)->len < 6) ? -1 : (buf)->data[5])

typedef int (*ssh_host_identity_checker)(const char *hostname, const struct SSH_STRING *host_key);
typedef int (*ssh_password_reader)(const char *hostname, const char *username, char *password, size_t max_len, int retry);

struct SSH_CONN;

enum SSH_CONN_DIRECTION {
  SSH_CONN_CTS,
  SSH_CONN_STC,
};

struct SSH_CONN *ssh_conn_new(void);
int ssh_conn_open(struct SSH_CONN *conn, const char *server, const char *port);
void ssh_conn_close(struct SSH_CONN *conn);
void ssh_conn_free(struct SSH_CONN *conn);

struct SSH_STRING ssh_conn_get_server_hostname(struct SSH_CONN *conn);
int ssh_conn_set_client_software(struct SSH_CONN *conn, const char *software, const char *comments);
void ssh_conn_set_server_identity_checker(struct SSH_CONN *conn, ssh_host_identity_checker checker);
int ssh_conn_set_username(struct SSH_CONN *conn, const char *username);
struct SSH_STRING ssh_conn_get_username(struct SSH_CONN *conn);
void ssh_conn_set_password_reader(struct SSH_CONN *conn, ssh_password_reader reader);
ssh_password_reader ssh_conn_get_password_reader(struct SSH_CONN *conn);

struct SSH_VERSION_STRING *ssh_conn_get_client_version_string(struct SSH_CONN *conn);
struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn);
void ssh_conn_set_session_id(struct SSH_CONN *conn, struct SSH_STRING *session_id);
struct SSH_STRING *ssh_conn_get_session_id(struct SSH_CONN *conn);
struct SSH_STRING *ssh_conn_get_session_id(struct SSH_CONN *conn);
int ssh_conn_set_cipher(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_CIPHER_TYPE type, struct SSH_STRING *iv, struct SSH_STRING *key);
int ssh_conn_set_mac(struct SSH_CONN *conn, enum SSH_CONN_DIRECTION dir, enum SSH_MAC_TYPE type, struct SSH_STRING *key);
int ssh_conn_check_server_identity(struct SSH_CONN *conn, struct SSH_STRING *server_host_key);

struct SSH_BUFFER *ssh_conn_new_packet(struct SSH_CONN *conn);
int ssh_conn_send_packet(struct SSH_CONN *conn);

struct SSH_BUF_READER *ssh_conn_recv_packet(struct SSH_CONN *conn);
struct SSH_BUF_READER *ssh_conn_recv_packet_skip_ignore(struct SSH_CONN *conn);

#endif /* CONNECTION_H_FILE */
