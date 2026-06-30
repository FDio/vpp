/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_armada_musdk_internal_h
#define included_armada_musdk_internal_h

#include <musdk.h>

struct base_addr
{
  uintptr_t va;
  phys_addr_t pa;
};

struct pp2_bm_pool
{
  u32 bm_pool_id;
  u32 bm_pool_buf_num;
  u32 bm_pool_buf_sz;
  u32 pp2_id;
  uintptr_t bm_pool_virt_base;
  uintptr_t bm_pool_phys_base;
  int fc_not_supported;
};

struct device_node;

const u32 *mv_of_get_address (struct device_node *, int, u64 *, u32 *);
u64 mv_of_translate_address (struct device_node *, const u32 *);
struct device_node *mv_of_find_compatible_node_by_indx (const struct device_node *, int,
							const char *, const char *);

#define UIO_MAX_NAME_SIZE 64
#define MAX_UIO_MAPS	  5

struct uio_map_t
{
  unsigned long addr;
  unsigned long size;
  char name[UIO_MAX_NAME_SIZE];
  int mmap_result;
  void *internal_addr;
};

struct uio_dev_attr_t
{
  char name[UIO_MAX_NAME_SIZE];
  char value[UIO_MAX_NAME_SIZE];
  struct uio_dev_attr_t *next;
};

struct uio_info_t
{
  int uio_num;
  struct uio_map_t maps[MAX_UIO_MAPS];
  unsigned long event_count;
  char name[UIO_MAX_NAME_SIZE];
  char version[UIO_MAX_NAME_SIZE];
  struct uio_dev_attr_t *dev_attrs;
  struct uio_info_t *next;
};

struct uio_mem_t
{
  int map_num;
  int fd;
  struct uio_info_t *info;
  struct uio_mem_t *next;
};

struct mem_uio
{
  struct uio_info_t *info;
  struct uio_mem_t *mem;
};

int musdk_is_init (void);
u32 musdk_num_instances (void);
u16 musdk_reserved_pool_map (void);
uintptr_t musdk_cpu_slot (u32, u32);
uintptr_t musdk_cm3_base (u32);
struct base_addr *musdk_regspaces (u32);
struct pp2_bm_pool *musdk_pool_slot_get (u32, u32);
void musdk_pool_slot_set (u32, u32, struct pp2_bm_pool *);
void musdk_release_descs (u32, u16, u32, struct pp2_ppio_desc[]);
uintptr_t musdk_port_cpu_slot (struct pp2_port *);
u32 musdk_port_pp2_id (struct pp2_port *);
u32 musdk_port_id (struct pp2_port *);
int musdk_port_fd (struct pp2_port *);
void musdk_port_fd_set (struct pp2_port *, int);

void pp2_bm_flush_pools (uintptr_t, u16);
void pp2_bm_pool_assign (struct pp2_port *, u32, u32, u32);

int iomem_uio_ioinit (struct mem_uio *, const char *, int);
int iomem_uio_iomap (struct mem_uio *, const char *, phys_addr_t *, void **);
int iomem_uio_iounmap (struct mem_uio *, const char *);
int iomem_uio_io_exists (const char *, int);
void iomem_uio_iodestroy (struct mem_uio *);
int pp2_port_open_uio (struct pp2_port *);
int pp2_port_close_uio (struct pp2_port *);

#endif /* included_armada_musdk_internal_h */
