/* ssh_constants.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ssh_constants.h"

static const struct MSG_NAME {
  uint8_t type;
  const char *name;
} msg_names[] = {
#define ADD_MSG_NAME(type) { type, #type }

  ADD_MSG_NAME(SSH_MSG_DISCONNECT),
  ADD_MSG_NAME(SSH_MSG_IGNORE),
  ADD_MSG_NAME(SSH_MSG_UNIMPLEMENTED),
  ADD_MSG_NAME(SSH_MSG_DEBUG),
  ADD_MSG_NAME(SSH_MSG_SERVICE_REQUEST),
  ADD_MSG_NAME(SSH_MSG_SERVICE_ACCEPT),
  ADD_MSG_NAME(SSH_MSG_KEXINIT),
  ADD_MSG_NAME(SSH_MSG_KEXDH_INIT),
  ADD_MSG_NAME(SSH_MSG_KEXDH_REPLY),
  ADD_MSG_NAME(SSH_MSG_NEWKEYS),
  ADD_MSG_NAME(SSH_MSG_USERAUTH_REQUEST),
  ADD_MSG_NAME(SSH_MSG_USERAUTH_FAILURE),
  ADD_MSG_NAME(SSH_MSG_USERAUTH_SUCCESS),
  ADD_MSG_NAME(SSH_MSG_USERAUTH_BANNER),
  ADD_MSG_NAME(SSH_MSG_GLOBAL_REQUEST),
  ADD_MSG_NAME(SSH_MSG_REQUEST_SUCCESS),
  ADD_MSG_NAME(SSH_MSG_REQUEST_FAILURE),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_OPEN),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_OPEN_CONFIRMATION),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_OPEN_FAILURE),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_WINDOW_ADJUST),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_DATA),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_EXTENDED_DATA),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_EOF),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_CLOSE),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_REQUEST),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_SUCCESS),
  ADD_MSG_NAME(SSH_MSG_CHANNEL_FAILURE),
  
#undef ADD_MSG_NAME
};

static char msg_unknown[256];

const char *ssh_const_get_msg_name(uint8_t msg_type)
{
  int i;
  
  for (i = 0; i < sizeof(msg_names)/sizeof(msg_names[0]); i++) {
    if (msg_names[i].type == msg_type)
      return msg_names[i].name;
  }
  
  snprintf(msg_unknown, sizeof(msg_unknown), "unknown message %d", msg_type);
  return msg_unknown;
}
