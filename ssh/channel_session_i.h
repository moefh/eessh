/* channel_session_i.h */

#ifndef CHANNEL_SESSION_I_H_FILE
#define CHANNEL_SESSION_I_H_FILE

#include "common/buffer.h"

struct SSH_CHAN;

int ssh_chan_session_opened(struct SSH_CHAN *chan);
int ssh_chan_session_process_packet(struct SSH_CHAN *chan, struct SSH_BUF_READER *pack);

#endif /* CHANNEL_SESSION_I_H_FILE */
