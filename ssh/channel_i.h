/* channel_i.h */

#ifndef CHANNEL_I_H_FILE
#define CHANNEL_I_H_FILE

#include "ssh/channel.h"

int ssh_chan_run_connection(struct SSH_CONN *conn, int num_channels, const struct SSH_CHAN_CONFIG *channel_cfgs);

#endif /* CHANNEL_I_H_FILE */
