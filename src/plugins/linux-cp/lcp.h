/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#ifndef __LCP_H__
#define __LCP_H__

#include <vlib/vlib.h>

#define LCP_NS_LEN 32

typedef struct lcp_main_s
{
  u16 msg_id_base;		    /* API message ID base */
  u8 *default_namespace;	    /* default namespace if set */
  int default_ns_fd;
  u8 lcp_auto_subint; /* Automatically create/delete LCP sub-interfaces */
  u8 lcp_sync;	      /* Automatically sync VPP changes to LCP */
  u8 test_mode;	      /* Set when Unit testing */
} lcp_main_t;

extern lcp_main_t lcp_main;

/**
 * Get/Set the default namespace for LCP host taps.
 */
int lcp_set_default_ns (u8 *ns);
u8 *lcp_get_default_ns (void); /* Returns NULL or shared string */
int lcp_get_default_ns_fd (void);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
