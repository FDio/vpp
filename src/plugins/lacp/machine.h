/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef	__LACP_MACHINE_H__
#define	__LACP_MACHINE_H__

#include <stdint.h>

#define LACP_NOACTION	((int (*)(void *, void *))0)
#define LACP_ACTION_ROUTINE(rtn) ((int(*)(void *, void *))rtn)

typedef int (*action_func) (void *, void *);

typedef struct
{
  action_func action;
  int next_state;
} lacp_fsm_state_t;

typedef void (*debug_func) (member_if_t * mif, int event, int state,
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
				  member_if_t * mif, int event, int *state);

#endif /* __LACP_MACHINE_H__ */
