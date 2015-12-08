/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_vnet_plugin_h
#define included_vnet_plugin_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>

/* Pointers to Genuine Vnet data structures handed to plugin .dll's */
typedef struct {
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;
} vnet_plugin_handoff_t;

void * vnet_get_handoff_structure (void);

#endif /* included_vnet_plugin_h */
