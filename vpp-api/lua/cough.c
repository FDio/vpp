/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * This is a temporary helper library to seamlessly run against
 * the current API as exposed by libpneum.
 * In the future once the sync API is exposed as well as
 * a way to free the received data, this can go away.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

pthread_mutex_t mut;
pthread_mutex_t *cb_lock = &mut;

void *pneum_handle = NULL;

typedef void* (*arbitrary)();

int (*orig_pneum_connect)(char *name, char *chroot_prefix) = NULL;
int (*orig_pneum_connect_sync)(char *name, char *chroot_prefix) = NULL;
int (*orig_pneum_disconnect)(void) = NULL;
int (*orig_pneum_read)(char **data, int *l) = NULL;
int (*orig_pneum_write)(char *data, int len) = NULL;
int (*orig_pneum_has_data)(void) = NULL;
int (*orig_pneum_data_free)(char *data) = NULL;

arbitrary my_function = NULL;

typedef uint8_t u8;
typedef uint32_t u32;

u8 *cough_read_buffer;
u32 cough_read_buffer_size = 1000000;
u32 cough_read_head = 0;
u32 cough_read_lock_start = 0; /* lock_start till head is busy memory */
u32 cough_read_tail = 0;


int wrap_pneum_callback(char *data, int len) {
  // printf("Cough callback! with %d bytes\n", len);
  pthread_mutex_lock(cb_lock);
  if(cough_read_lock_start == cough_read_head) {
    // printf("Reset read head!\n");
    cough_read_head = 0;
    cough_read_tail = 0;
    cough_read_lock_start = 0;
  }
  u32 store_len = len;
  memcpy(cough_read_buffer + cough_read_head, &store_len, sizeof(u32));
  cough_read_head += sizeof(u32);
  memcpy(cough_read_buffer + cough_read_head, data, len);
  cough_read_head += len;
  pthread_mutex_unlock(cb_lock);
  return len;
}

int cough_pneum_attach(char *pneum_fname, char *cough_fname) {
  /* this is needed to make the pneum aware of the wrap_pneum_callback */
  pneum_handle = dlopen(cough_fname, RTLD_NOW|RTLD_GLOBAL);
  /* now let's try to load pneum itself */
  pneum_handle = dlopen(pneum_fname, RTLD_NOW|RTLD_GLOBAL);
  if (pneum_handle) {
    *(void**)(&orig_pneum_connect) = dlsym(pneum_handle,"pneum_connect");
    *(void**)(&orig_pneum_connect_sync) = dlsym(pneum_handle,"pneum_connect_sync");
    *(void**)(&orig_pneum_disconnect) = dlsym(pneum_handle,"pneum_disconnect");
    *(void**)(&orig_pneum_read) = dlsym(pneum_handle,"pneum_read");
    *(void**)(&orig_pneum_write) = dlsym(pneum_handle,"pneum_write");
    *(void**)(&orig_pneum_has_data) = dlsym(pneum_handle,"pneum_has_data");
    *(void**)(&orig_pneum_data_free) = dlsym(pneum_handle,"pneum_data_free");
    // If you uncomment the below line we pretend we have an async-only libpneum
    orig_pneum_connect_sync = NULL;
    cough_read_buffer = malloc(cough_read_buffer_size);
  } else {
    printf("Could not get cough handle\n");
    printf("Error: %s", dlerror());
    return -1;
  }

  *(void**)(&my_function) = dlsym(pneum_handle,"something");
}


int pneum_connect(char *name, char *chroot_prefix) {
  if(orig_pneum_connect) {
    return(orig_pneum_connect(name, chroot_prefix));
  } else {
    printf("COUGH: pneum_connect\n");
    return -1;
  }
}
int pneum_connect_sync(char *name, char *chroot_prefix) {
  if(orig_pneum_connect_sync) {
    int ret = (orig_pneum_connect_sync(name, chroot_prefix));
    return ret;
  } else {
    return(orig_pneum_connect(name, chroot_prefix));
  }
}


int pneum_disconnect(void) {
  if(orig_pneum_disconnect) {
    return orig_pneum_disconnect();
  } else {
    printf("COUGH: pneum_disconnect\n");
    return -1;
  }
}

int pneum_has_data(void) {
  if (orig_pneum_connect_sync) {
    /* always return 1 in a pass-through case */
    return 1;
  } else {
    // printf("COUGH: pneum_has_data\n");
    return (cough_read_head != cough_read_tail);
  }
}


int pneum_read(char **data, int *l) {
  if(orig_pneum_connect_sync) {
    return orig_pneum_read(data, l);
  } else { 
    while(!pneum_has_data());
    u32 n_bytes;
    pthread_mutex_lock(cb_lock);
    memcpy(&n_bytes, cough_read_buffer + cough_read_tail, sizeof(u32));
    cough_read_tail += sizeof(u32);
    void * dataptr = (void *) (cough_read_buffer + cough_read_tail);
    *data = dataptr;
    cough_read_tail += n_bytes;
    *l = n_bytes;
    pthread_mutex_unlock(cb_lock);
    return n_bytes; 
  }
}

int pneum_write(char *data, int len) {
  if(orig_pneum_write) {
    return(orig_pneum_write(data, len));
  } else {
    printf("COUGH: pneum_write\n");
    return -1;
  }
}

void pneum_data_free(char *data) {
  if (orig_pneum_connect_sync) {
    if(orig_pneum_data_free) {
      orig_pneum_data_free(data);
    } else {
      printf("COUGH: pneum_data_free\n");
    }
  } else {
    u32 *len;
    uint32_t index = ((u8*)data) - cough_read_buffer;
    pthread_mutex_lock(cb_lock);
    if ((index < cough_read_head) && (index > cough_read_lock_start)) {
      len = (void *)(data - sizeof(u32));
      cough_read_lock_start = index + *len;
    }
    pthread_mutex_unlock(cb_lock);
  }
}
