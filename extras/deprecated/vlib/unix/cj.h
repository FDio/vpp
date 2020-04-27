/*
 *------------------------------------------------------------------
 * cj.h
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __included_cj_h__
#define __included_cj_h__

typedef struct
{
  f64 time;
  u32 thread_index;
  u32 type;
  u64 data[2];
} cj_record_t;

typedef struct
{
  volatile u64 tail;
  cj_record_t *records;
  u32 num_records;
  volatile u32 enable;

  vlib_main_t *vlib_main;
} cj_main_t;

void cj_log (u32 type, void *data0, void *data1);

/*
 * Supply in application main, so we can log from any library...
 * Declare a weak reference in the library, off you go.
 */

#define DECLARE_CJ_GLOBAL_LOG                                   \
void cj_global_log (unsigned type, void * data0, void * data1)  \
  __attribute__ ((weak));                                       \
                                                                \
unsigned __cj_type;                                             \
void * __cj_data0;                                              \
void * __cj_data1;                                              \
                                                                \
void                                                            \
cj_global_log (unsigned type, void * data0, void * data1)       \
{                                                               \
  __cj_type = type;                                             \
  __cj_data0 = data0;                                           \
  __cj_data1 = data1;                                           \
}

#define CJ_GLOBAL_LOG_PROTOTYPE
void
cj_global_log (unsigned type, void *data0, void *data1)
__attribute__ ((weak));

void cj_stop (void);

#endif /* __included_cj_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
