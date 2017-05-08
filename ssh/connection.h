/* connection.h */

#ifndef CONNECTION_H_FILE
#define CONNECTION_H_FILE

#include "common/buffer.h"
#include "ssh/version_string.h"
#include "ssh/channel.h"

#define ssh_packet_get_type(buf)  (((buf)->len < 6) ? -1 : (buf)->data[5])

typedef int (*ssh_conn_host_identity_checker)(const char *hostname, const struct SSH_STRING *host_key);
typedef int (*ssh_conn_password_reader)(const char *hostname, const char *username, char *password, size_t max_len, int retry);

struct SSH_CONN_CONFIG {
  const char *server;
  const char *port;
  const char *username;
  const char *version_software;
  const char *version_comments;
  ssh_conn_host_identity_checker server_identity_checker;
  ssh_conn_password_reader password_reader;
};

struct SSH_CONN;

struct SSH_CONN *ssh_conn_open(const struct SSH_CONN_CONFIG *config);
void ssh_conn_close(struct SSH_CONN *conn);

int ssh_conn_run(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs);

struct SSH_VERSION_STRING *ssh_conn_get_client_version_string(struct SSH_CONN *conn);
struct SSH_VERSION_STRING *ssh_conn_get_server_version_string(struct SSH_CONN *conn);

#endif /* CONNECTION_H_FILE */
