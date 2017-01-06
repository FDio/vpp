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
#ifndef included_pneum_h
#define included_pneum_h

#include <stdint.h>
#include <vppinfra/types.h>

typedef void (*pneum_callback_t)(unsigned char * data, int len);
int pneum_connect(char * name, char * chroot_prefix, pneum_callback_t cb,
    int rx_qlen);
int pneum_disconnect(void);
int pneum_read(char **data, int *l);
int pneum_write(char *data, int len);
void pneum_free(void * msg);
uword * pneum_msg_table_get_hash (void);
int pneum_msg_table_size(void);
uint32_t pneum_get_msg_index(unsigned char * name);

#endif
