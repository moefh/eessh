/* network_i.h */

#ifndef NETWORK_I_H_FILE
#define NETWORK_I_H_FILE

int ssh_net_connect(const char *server, const char *port);
int ssh_net_set_sock_blocking(int sock, int block);
ssize_t ssh_net_write(int sock, const void *data, size_t len);
ssize_t ssh_net_read(int sock, void *data, size_t max_len);

#endif /* NETWORK_I_H_FILE */

