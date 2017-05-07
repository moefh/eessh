/* connection.h */

#ifndef CONNECTION_H_FILE
#define CONNECTION_H_FILE

#include "common/buffer.h"
#include "ssh/version_string.h"

#define ssh_packet_get_type(buf)  (((buf)->len < 6) ? -1 : (buf)->data[5])

typedef int (*ssh_conn_host_identity_checker)(const char *hostname, const struct SSH_STRING *host_key);
typedef int (*ssh_conn_password_reader)(const char *hostname, const char *username, char *password, size_t max_len, int retry);

struct SSH_CONN;

enum SSH_CONN_DIRECTION {
  SSH_CONN_CTS,
  SSH_CONN_STC,
};

struct SSH_CONN *ssh_conn_new(void);
int ssh_conn_open(struct SSH_CONN *conn, const char *server, const char *port);
void ssh_conn_close(struct SSH_CONN *conn);
void ssh_conn_free(struct SSH_CONN *conn);

int ssh_conn_set_client_software(struct SSH_CONN *conn, const char *software, const char *comments);
void ssh_conn_set_server_identity_checker(struct SSH_CONN *conn, ssh_conn_host_identity_checker checker);
int ssh_conn_set_username(struct SSH_CONN *conn, const char *username);
void ssh_conn_set_password_reader(struct SSH_CONN *conn, ssh_conn_password_reader reader);

struct SSH_VERSION_STRING *ssh_conn_get_client_version_string(struct SSH_CONN *conn);
struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn);

#endif /* CONNECTION_H_FILE */
