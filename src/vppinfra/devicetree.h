/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef CLIB_DEVICETREE_H_
#define CLIB_DEVICETREE_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>

#ifdef __linux
#define CLIB_DT_LINUX_PREFIX "/sys/firmware/devicetree/base"
#endif

typedef struct
{
  char name[32];
  u32 size;
  u8 data[];
} clib_dt_property_t;

typedef struct clib_dt_main clib_dt_main_t;

typedef struct clib_dt_node
{
  u8 *path;
  struct clib_dt_node *parent;
  struct clib_dt_node *prev;
  struct clib_dt_node *next;
  struct clib_dt_node **child_nodes;
  u8 depth;
  clib_dt_property_t *name;
  clib_dt_property_t **properties;
  clib_dt_main_t *dt_main;
} clib_dt_node_t;

typedef struct clib_dt_main
{
  clib_dt_node_t **nodes;
  clib_dt_node_t *root;
  uword *node_by_path;
  uword *node_by_phandle;
} clib_dt_main_t;

clib_dt_node_t *clib_dt_get_node_with_path (clib_dt_main_t *dm, char *fmt,
					    ...);
clib_dt_property_t *clib_dt_get_node_property_by_name (clib_dt_node_t *,
						       char *);
int clib_dt_node_is_compatible (clib_dt_node_t *, char *);
clib_dt_node_t *clib_dt_dereference_node (clib_dt_node_t *, char *);
#ifdef __linux
clib_error_t *clib_dt_read_from_sysfs (clib_dt_main_t *dm);
#endif

format_function_t format_clib_dt_desc;
format_function_t format_clib_dt_property_data;

static_always_inline int
clib_dt_proprerty_is_u32 (clib_dt_property_t *p)
{
  if (p == 0 || p->size != 4)
    return 0;
  return 1;
}

static_always_inline u32
clib_dt_proprerty_get_u32 (clib_dt_property_t *p)
{
  return clib_net_to_host_u32 (*(u32u *) p->data);
}

#endif /* CLIB_DEVICETREE_H_ */
