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
#ifndef included_vppapiclient_h
#define included_vppapiclient_h

#include <stdint.h>
#include <stdbool.h>

#define VAC_NOT_CONNECTED -3
#define VAC_SHM_NOT_READY -4
#define VAC_TIMEOUT -5

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
