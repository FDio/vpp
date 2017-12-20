/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef	__VNET_BONDING_LACP_MACHINE_H__
#define	__VNET_BONDING_LACP_MACHINE_H__

#include <stdint.h>

#define LACP_NOACTION	((int (*)(void *, void *))0)
#define LACP_ACTION_ROUTINE(rtn) ((int(*)(void *, void *))rtn)

typedef int (*action_func) (void *, void *);

typedef struct
{
  action_func action;
  int next_state;
} lacp_fsm_state_t;

typedef void (*debug_func) (slave_if_t * sif, int event, int state,
			    lacp_fsm_state_t * transition);

typedef struct
{
  lacp_fsm_state_t *state_table;
} lacp_fsm_machine_t;

typedef struct
{
  lacp_fsm_machine_t *tables;
  debug_func debug;
} lacp_machine_t;

extern int lacp_machine_dispatch (lacp_machine_t * machine, vlib_main_t * vm,
				  slave_if_t * sif, int event, int *state);

#endif /* __VNET_BONDING_LACP_MACHINE_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
