/* host_key_store.c */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common/host_key_store.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/alloc.h"
#include "common/base64.h"

#define MAX_LINE_SIZE  1024

typedef int (*key_file_line_callback)(char *line, void *p);

struct HOST_DATA {
  const char *hostname;
  char *key_type;
  char *host_key;
};

struct SEARCH_HOST_DATA {
  struct HOST_DATA host_data;
  enum SSH_HOST_KEY_STORE_STATUS search_result;
};

struct ADD_HOST_DATA {
  FILE *out;
  struct HOST_DATA host_data;
  int replaced_host_key;
};

static int host_data_create(struct HOST_DATA *host_data, const char *hostname, const struct SSH_STRING *host_key)
{
  struct SSH_BUF_READER reader = ssh_buf_reader_new_from_string((struct SSH_STRING *) host_key);
  struct SSH_STRING key_type;
  
  if (ssh_buf_read_string(&reader, &key_type) < 0)
    return -1;
  host_data->key_type = ssh_alloc(key_type.len + 1);
  if (host_data->key_type == NULL) {
    ssh_set_error("error reading host key type");
    return -1;
  }
  memcpy(host_data->key_type, key_type.str, key_type.len);
  
  host_data->host_key = base64_encode(host_key->str, host_key->len);
  if (host_data->host_key == NULL) {
    ssh_free(host_data->key_type);
    return -1;
  }
  
  host_data->hostname = hostname;
  return 0;
}

static void host_data_free(struct HOST_DATA *host_data)
{
  ssh_free(host_data->key_type);
  host_data->key_type = NULL;
  ssh_free(host_data->host_key);
  host_data->host_key = NULL;
}

static int read_key_file(FILE *f, key_file_line_callback callback, void *callback_data)
{
  char line[MAX_LINE_SIZE];
  size_t line_len;
  int ret = 0;
  int has_error = 0;

  while (1) {
    if (fgets(line, MAX_LINE_SIZE, f) == NULL) {
      if (ferror(f)) {
        ssh_set_error("error reading file");
        has_error = 1;
      }
      break;
    }
    line_len = strlen(line);
    if (line_len > 0 && line[line_len-1] != '\n') {
        ssh_set_error("line too long");
        has_error = 1;
        break;
    }

    ret = callback(line, callback_data);
    if (ret != 0)
      break;
  }

  fclose(f);
  return (has_error) ? -1 : ret;
}

static enum SSH_HOST_KEY_STORE_STATUS line_matches_key(char *line, struct HOST_DATA *host_data)
{
  char *hostname, *key_type, *host_key, *save;

  //printf("-> matching line: %s", line);
  
  hostname = strtok_r(line, " \t\r\n", &save);
  if (hostname == NULL || *hostname == '#' || strcmp(hostname, host_data->hostname) != 0)
    return SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND;

  key_type = strtok_r(NULL, " \t\r\n", &save);
  if (key_type == NULL || strcmp(key_type, host_data->key_type) != 0)
    return SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND;

  host_key = strtok_r(NULL, " \t\r\n", &save);
  if (host_key == NULL || strcmp(host_key, host_data->host_key) != 0)
    return SSH_HOST_KEY_STORE_STATUS_ERR_BAD_IDENTITY;

  return SSH_HOST_KEY_STORE_STATUS_OK;
}

static int add_key_callback(char *line, void *data)
{
  struct ADD_HOST_DATA *add_data = data;

  if (line_matches_key(line, &add_data->host_data) != SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND) {
    fprintf(add_data->out, "%s %s %s\n", add_data->host_data.hostname, add_data->host_data.key_type, add_data->host_data.host_key);
    add_data->replaced_host_key = 1;
  } else
    fwrite(line, 1, strlen(line), add_data->out);

  if (ferror(add_data->out)) {
    ssh_set_error("error writing file");
    return -1;
  }
  return 0;
}

int ssh_host_key_store_add(const char *filename, const char *hostname, const struct SSH_STRING *server_host_key)
{
  FILE *in;
  char new_filename[1024];
  size_t new_filename_len;
  struct ADD_HOST_DATA add_data;
  int ret;
  mode_t old_umask;

  new_filename_len = snprintf(new_filename, sizeof(new_filename), "%s.%u", filename, (unsigned int) getpid());
  if (strlen(new_filename) != new_filename_len) {
    ssh_set_error("file name too long");
    return -1;
  }

  old_umask = umask(0077);
  add_data.out = fopen(new_filename, "w");
  umask(old_umask);
  if (add_data.out == NULL) {
    ssh_set_error("can't create temporary file");
    return -1;
  }
  if (host_data_create(&add_data.host_data, hostname, server_host_key) < 0) {
    fclose(add_data.out);
    return -1;
  }
  add_data.replaced_host_key = 0;

  in = fopen(filename, "r");
  if (in == NULL) {
    if (errno == ENOENT)
      ret = 0;
    else {
      ssh_set_error("can't open file");
      ret = -1;
    }
  } else {
    ret = read_key_file(in, add_key_callback, &add_data);
  }
  
  if (ret >= 0 && ! add_data.replaced_host_key) {
    fprintf(add_data.out, "%s %s %s\n", add_data.host_data.hostname, add_data.host_data.key_type, add_data.host_data.host_key);
    if (ferror(add_data.out)) {
      ssh_set_error("error writing file");
      ret = -1;
    }
  }
  
  host_data_free(&add_data.host_data);
  fclose(add_data.out);
  
  if (ret >= 0) {
    if (rename(new_filename, filename) != 0) {
      unlink(new_filename);
      ssh_set_error("can't replace file");
      ret = -1;
    }
  } else
    unlink(new_filename);

  return ret;
}

static int search_key_callback(char *line, void *data)
{
  struct SEARCH_HOST_DATA *search_data = data;
  enum SSH_HOST_KEY_STORE_STATUS search_result;
  
  search_result = line_matches_key(line, &search_data->host_data);
  switch (search_result) {
  case SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND:
    return 0;

  case SSH_HOST_KEY_STORE_STATUS_ERR_BAD_IDENTITY:
  case SSH_HOST_KEY_STORE_STATUS_OK:
    search_data->search_result = search_result;
    return 1;

  default:
    return -1;
  }
}

enum SSH_HOST_KEY_STORE_STATUS ssh_host_key_store_check_server(const char *filename, const char *hostname, const struct SSH_STRING *server_host_key)
{
  struct SEARCH_HOST_DATA search_data;
  enum SSH_HOST_KEY_STORE_STATUS search_result;
  FILE *in;
  int ret;

  in = fopen(filename, "r");
  if (in == NULL) {
    if (errno == ENOENT)
      return SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND;
    ssh_set_error("can't open key store file");
    return SSH_HOST_KEY_STORE_STATUS_ERR_OTHER;
  }

  if (host_data_create(&search_data.host_data, hostname, server_host_key) < 0) {
    fclose(in);
    return SSH_HOST_KEY_STORE_STATUS_ERR_OTHER;
  }
  search_data.search_result = SSH_HOST_KEY_STORE_STATUS_ERR_NOT_FOUND;

  ret = read_key_file(in, search_key_callback, &search_data);

  search_result = search_data.search_result;
  host_data_free(&search_data.host_data);
  if (ret < 0)
    return SSH_HOST_KEY_STORE_STATUS_ERR_OTHER;
  return search_result;
}
