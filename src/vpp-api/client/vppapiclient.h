/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef included_vppapiclient_h
#define included_vppapiclient_h

#include <stdint.h>
#include <stdbool.h>

typedef enum
{
  VAC_SVM_QUEUE_SUB_1 = -1,
  VAC_SVM_QUEUE_SUB_2 = -2,
  VAC_NOT_CONNECTED = -3,
  VAC_SHM_NOT_READY = -4,
  VAC_TIMEOUT = -5,
} vac_errno_t;

typedef void (*vac_callback_t)(unsigned char * data, int len);
typedef void (*vac_error_callback_t)(void *, unsigned char *, int);
int vac_connect(char * name, char * chroot_prefix, vac_callback_t cb,
    int rx_qlen);
int vac_disconnect(void);
int vac_read(char **data, int *l, unsigned short timeout);
int vac_write(char *data, int len);
void vac_free(void * msg);

int vac_get_msg_index(char * name);
int vac_msg_table_size(void);
int vac_msg_table_max_index(void);

void vac_rx_suspend (void);
void vac_rx_resume (void);
void vac_set_error_handler(vac_error_callback_t);
void vac_mem_init (size_t size);

#endif
