/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Rubicon Communications, LLC.
 */

#define GRAPH_NODE_NAME_LEN	64

typedef struct
{
  u16 msg_id_base;
  vlib_node_t **sorted_node_vec;
} graph_main_t;

extern graph_main_t graph_main;
