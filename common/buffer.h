/* buffer.h */

#ifndef BUFFER_H_FILE
#define BUFFER_H_FILE

#include <stddef.h>
#include <stdint.h>

struct SSH_BUFFER {
  uint8_t *data;
  size_t cap;
  size_t len;
};

struct SSH_BUF_READER {
  uint8_t *data;
  size_t pos;
  size_t len;
};

struct SSH_STRING {
  uint8_t *str;
  size_t len;
};

uint32_t ssh_buf_get_u32(uint8_t *data);
void ssh_buf_set_u32(uint8_t *data, uint32_t v);

struct SSH_STRING ssh_str_new(uint8_t *data, size_t len);
struct SSH_STRING ssh_str_new_empty(void);
struct SSH_STRING ssh_str_new_from_buffer(struct SSH_BUFFER *buf);
int ssh_str_alloc(struct SSH_STRING *new_str, size_t len);
int ssh_str_dup_string(struct SSH_STRING *new_str, const struct SSH_STRING *str);
void ssh_str_free(struct SSH_STRING *str);

struct SSH_BUFFER ssh_buf_new(void);
struct SSH_BUFFER ssh_buf_new_from_data(uint8_t *data, size_t len);
void ssh_buf_free(struct SSH_BUFFER *buf);
void ssh_buf_clear(struct SSH_BUFFER *buf);
int ssh_buf_grow(struct SSH_BUFFER *buf, size_t add_len);
int ssh_buf_ensure_size(struct SSH_BUFFER *buf, size_t new_len);
uint8_t *ssh_buf_get_write_pointer(struct SSH_BUFFER *buf, size_t len);
int ssh_buf_write_u8(struct SSH_BUFFER *buf, uint8_t val);
int ssh_buf_write_u32(struct SSH_BUFFER *buf, uint32_t val);
int ssh_buf_write_cstring(struct SSH_BUFFER *buf, const char *val);
int ssh_buf_write_cstring_n(struct SSH_BUFFER *buf, const char *val, size_t len);
int ssh_buf_write_string(struct SSH_BUFFER *buf, const struct SSH_STRING *val);
int ssh_buf_write_buffer(struct SSH_BUFFER *buf, const struct SSH_BUFFER *val);
int ssh_buf_write_buf_reader(struct SSH_BUFFER *buf, const struct SSH_BUF_READER *val);
int ssh_buf_append_data(struct SSH_BUFFER *buf, const uint8_t *data, size_t len);
#define ssh_buf_append_u8 ssh_buf_write_u8
#define ssh_buf_append_u32 ssh_buf_write_u32
int ssh_buf_append_cstring(struct SSH_BUFFER *buf, const char *val);
int ssh_buf_append_cstring_n(struct SSH_BUFFER *buf, const char *val, size_t len);
int ssh_buf_append_string(struct SSH_BUFFER *buf, const struct SSH_STRING *val);
int ssh_buf_append_buffer(struct SSH_BUFFER *buf, const struct SSH_BUFFER *val);
int ssh_buf_append_buf_reader(struct SSH_BUFFER *buf, const struct SSH_BUF_READER *val);
int ssh_buf_remove_data(struct SSH_BUFFER *buf, size_t offset, size_t len);

struct SSH_BUF_READER ssh_buf_reader_new(uint8_t *data, size_t len);
struct SSH_BUF_READER ssh_buf_reader_new_from_buffer(struct SSH_BUFFER *buf);
struct SSH_BUF_READER ssh_buf_reader_new_from_string(struct SSH_STRING *str);
void ssh_buf_reader_rewind(struct SSH_BUF_READER *buf);
int ssh_buf_read_u8(struct SSH_BUF_READER *buf, uint8_t *ret_val);
int ssh_buf_read_u32(struct SSH_BUF_READER *buf, uint32_t *ret_val);
int ssh_buf_read_string(struct SSH_BUF_READER *buf, struct SSH_STRING *ret_val);
int ssh_buf_read_until(struct SSH_BUF_READER *buf, uint8_t sentinel, struct SSH_STRING *ret_val);
int ssh_buf_read_skip(struct SSH_BUF_READER *buf, size_t len);

#endif /* BUFFER_H_FILE */
