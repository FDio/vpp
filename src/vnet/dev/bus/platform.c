/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "devicetree",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U" f,                      \
	    format_vnet_dev_log_prefix, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U" f,                        \
	    format_vnet_dev_log_prefix, dev, ##__VA_ARGS__)

#define DEVICETREE_PREFIX "/sys/firmware/devicetree/base"
#define PLATFORM_DEV_PATH "/sys/bus/platform/devices"

vnet_dev_dt_main_t vnet_dev_dt_main;

static_always_inline vnet_dev_dt_node_t *
vnet_dev_dt_node_add_child (vnet_dev_dt_node_t *n, char *name)
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  vnet_dev_dt_node_t *cn;

  cn = clib_mem_alloc (sizeof (vnet_dev_dt_node_t));
  *cn = (vnet_dev_dt_node_t){ .parent = n, .depth = n ? n->depth + 1 : 0 };
  vec_add1 (dm->nodes, cn);

  if (n == 0)
    {
      ASSERT (dm->root == 0);
      dm->root = cn;
      return cn;
    }

  vec_add1 (n->child_nodes, cn);
  cn->path = format (0, "%v/%s", n->path, name);
  hash_set_mem (dm->node_by_path, cn->path, cn);
  if (vec_len (n->child_nodes) > 1)
    {
      vnet_dev_dt_node_t *prev = n->child_nodes[vec_len (n->child_nodes) - 2];
      prev->next = cn;
      cn->prev = prev;
    }

  return cn;
}

void
vnet_dev_dt_main_free ()
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  vec_foreach_pointer (n, dm->nodes)
    {
      vec_foreach_pointer (p, n->properties)
	clib_mem_free (p);
      vec_free (n->child_nodes);
      vec_free (n->path);
      vec_free (n->properties);
    }

  vec_free (dm->nodes);
  hash_free (dm->node_by_path);
}

vnet_dev_rv_t
fdt_read_from_sysfs ()
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  DIR *dir, **dir_stack = 0;
  struct dirent *e;
  vnet_dev_dt_node_t *n;
  u8 *path = 0;
  u32 path_prefix_len;
  vnet_dev_rv_t rv = VNET_DEV_ERR_BUS;

  path = format (0, DEVICETREE_PREFIX);
  path_prefix_len = vec_len (path);
  vec_add1 (path, 0);

  dir = opendir ((char *) path);
  if (!dir)
    {
      log_err (0, "'%s' opendir failed", path);
      goto done;
    }

  dm->node_by_path = hash_create_vec (0, sizeof (u8), sizeof (uword));
  dm->node_by_phandle = hash_create (0, sizeof (uword));
  vec_set_len (path, path_prefix_len);
  n = vnet_dev_dt_node_add_child (0, 0);

  while (1)
    {
      e = readdir (dir);

      if (!e)
	{
	  closedir (dir);
	  if (vec_len (dir_stack) == 0)
	    {
	      rv = VNET_DEV_OK;
	      break;
	    }

	  dir = dir_stack[vec_len (dir_stack) - 1];
	  vec_pop (dir_stack);
	  n = n->parent;
	  continue;
	}

      if (e->d_type == DT_REG)
	{
	  path = format (path, "%v/%s%c", n->path, e->d_name, 0);
	  int fd = open ((char *) path, 0);
	  if (fd >= 0)
	    {
	      struct stat st;
	      if (fstat (fd, &st) == 0)
		{
		  u32 sz = sizeof (vnet_dev_dt_property_t) + st.st_size;
		  vnet_dev_dt_property_t *p = clib_mem_alloc (sz);
		  clib_memset (p, 0, sz);

		  if (read (fd, p->data, st.st_size) == st.st_size)
		    {
		      strncpy (p->name, e->d_name, sizeof (p->name));
		      p->size = st.st_size;
		      vec_add1 (n->properties, p);
		      if (strncmp ("name", p->name, 5) == 0)
			n->name = p;
		      if ((strncmp ("phandle", p->name, 8) == 0) &&
			  (p->size == 4))
			{
			  u32 phandle =
			    clib_net_to_host_u32 (*(u32u *) p->data);
			  hash_set (dm->node_by_phandle, phandle, n);
			}
		    }
		  else
		    {
		      clib_mem_free (p);
		      log_err (0, "'%s' read failed", path);
		      close (fd);
		      goto done;
		    }
		}
	      else
		{
		  log_err (0, "'%s' fstat failed", path);
		  close (fd);
		  goto done;
		}
	      close (fd);
	    }
	  else
	    {
	      log_err (0, "'%s' open failed", path);
	      goto done;
	    }

	  vec_set_len (path, path_prefix_len);
	}
      else if (e->d_type == DT_DIR)
	{
	  DIR *subdir;
	  if (strncmp (".", e->d_name, 2) == 0 ||
	      strncmp ("..", e->d_name, 3) == 0)
	    continue;

	  path = format (path, "%v/%s%c", n->path, e->d_name, 0);
	  subdir = opendir ((char *) path);
	  vec_set_len (path, path_prefix_len);
	  if (subdir)
	    {
	      vec_add1 (dir_stack, dir);
	      dir = subdir;
	      n = vnet_dev_dt_node_add_child (n, e->d_name);
	    }
	  else
	    {
	      log_err (0, "'%s' opendir failed", path);
	      goto done;
	    }
	}
      else
	log_debug (0, "unknown entry %s [%u]", e->d_name, e->d_type);
    }

done:
  if (rv != VNET_DEV_OK)
    vnet_dev_dt_main_free ();
  while (vec_len (dir_stack))
    closedir (vec_pop (dir_stack));
  vec_free (dir_stack);
  vec_free (path);
  return rv;
}

vnet_dev_dt_node_t *
vnet_dev_dt_get_child_node (vnet_dev_dt_node_t *n, char *name)
{
  vec_foreach_pointer (cn, n->child_nodes)
    {
      u8 *p = cn->path + vec_len (cn->path) - 1;
      u32 i = 0;

      while (p > cn->path && p[-1] != '/')
	p--;

      if (p[-1] != '/')
	continue;

      while (p[i] == name[i] && name[i] != 0)
	i++;

      if (name[i] != 0)
	continue;

      return cn;
    }

  return 0;
}

vnet_dev_dt_node_t *
vnet_dev_dt_get_node_with_path (char *fmt, ...)
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  u8 *s;
  uword *p;

  va_list va;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (s[0] != '/')
    return 0;

  p = hash_get_mem (dm->node_by_path, s);
  if (p)
    return (vnet_dev_dt_node_t *) p[0];

  return 0;
}

vnet_dev_dt_property_t *
vnet_dev_dt_get_node_property_by_name (vnet_dev_dt_node_t *n, char *name)
{
  vec_foreach_pointer (p, n->properties)
    if (strncmp (name, p->name, sizeof (p->name)) == 0)
      return p;
  return 0;
}

vnet_dev_rv_t
vnet_dev_bus_platform_dt_node_from_device_id (vnet_dev_dt_node_t **nodep,
					      char *device_id)
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_dt_node_t *n;
  char *name = device_id + sizeof (PLATFORM_BUS_NAME);
  char path[PATH_MAX];
  int r;
  u8 *link;

  if (dm->root == 0)
    {
      rv = fdt_read_from_sysfs ();
      if (rv != VNET_DEV_OK)
	return 0;
    }

  link = format (0, PLATFORM_DEV_PATH "/%s/of_node%c", name, 0);
  r = readlink ((char *) link, path, sizeof (path) - 1);

  if (r < 1)
    {
      log_err (0, "of_node doesn't exist for '%s'", name);
      vec_free (link);
      return VNET_DEV_ERR_NOT_FOUND;
    }

  path[r] = 0;
  vec_reset_length (link);
  link = format (link, PLATFORM_DEV_PATH "/%s/%s%c", name, path, 0);
  realpath ((char *) link, path);
  vec_free (link);

  if (strncmp (DEVICETREE_PREFIX, path, sizeof (DEVICETREE_PREFIX) - 1) != 0)
    return VNET_DEV_ERR_BUG;

  n = vnet_dev_dt_get_node_with_path ("%s",
				      path + sizeof (DEVICETREE_PREFIX) - 1);

  if (n)
    {
      *nodep = n;
      return VNET_DEV_OK;
    }

  return VNET_DEV_ERR_NOT_FOUND;
}

static void *
vnet_dev_dt_get_device_info (vlib_main_t *vm, char *device_id)
{
  vnet_dev_dt_node_t *n = 0;
  vnet_dev_bus_platform_device_info_t *di;

  vnet_dev_bus_platform_dt_node_from_device_id (&n, device_id);

  if (n)
    {
      vnet_dev_dt_property_t *compatible;
      compatible = vnet_dev_dt_get_node_property_by_name (n, "compatible");
      log_debug (0, "node found, is compatible %U",
		 format_vnet_dev_dt_property_data, compatible);
      di = clib_mem_alloc (sizeof (*di));
      di->node = n;
      return di;
    }

  return 0;
}

static void
vnet_dev_dt_free_device_info (vlib_main_t *vm, void *p)
{
  clib_mem_free (p);
}

static void
vnet_dev_dt_close (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static vnet_dev_rv_t
vnet_dev_dt_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_dt_node_t *n = 0;
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_rv_t rv;

  rv = vnet_dev_bus_platform_dt_node_from_device_id (&n, dev->device_id);
  if (rv != VNET_DEV_OK)
    return rv;

  dd->node = n;
  return VNET_DEV_OK;
}

int
vnet_dev_dt_node_is_compatible (vnet_dev_dt_node_t *n, char *comp)
{
  vnet_dev_dt_property_t *p;
  char *s;

  p = vnet_dev_dt_get_node_property_by_name (n, "compatible");

  if (!p)
    return 0;

  s = (char *) p->data;
  for (u32 i = 1, len = 1; i <= p->size; i++)
    {
      if (p->data[i - 1] == 0)
	{
	  if (strncmp (comp, s, len) == 0)
	    return 1;
	  s = (char *) p->data + i;
	  len = 1;
	}
      else
	len++;
    }

  return 0;
}

u8 *
format_vnet_dev_dt_property_data (u8 *s, va_list *args)
{
  vnet_dev_dt_property_t *p = va_arg (*args, vnet_dev_dt_property_t *);
  u32 sz = p->size, is_printable = 0;
  u32 n_nulls = 0;

  if (sz > 2 && p->data[sz - 1] == 0 && p->data[0] != 0)
    {
      is_printable = 1;
      for (u32 i = 1; i < sz - 1; i++)
	{
	  u8 c = p->data[i];
	  if (c == 0)
	    {
	      if (p->data[i - 1] == 0)
		{
		  is_printable = 0;
		  break;
		}
	      n_nulls++;
	    }
	  else if ((c < 0x20) || (c > 0x7f))
	    {
	      is_printable = 0;
	      break;
	    }
	}
    }

  if (is_printable)
    {
      s = format (s, "'%s'", p->data);
      if (n_nulls)
	{
	  for (u32 i = 2; i < p->size; i++)
	    if (((u8 *) p->data)[i - 1] == 0)
	      s = format (s, ", '%s'", ((u8 *) p->data) + i);
	}
    }
  else
    {
      s = format (s, "< %02x", p->data[0]);
      for (u32 i = 0; i < p->size; i++)
	s = format (s, " %02x", p->data[i]);
      s = format (s, " >");
    }
  return s;
}

vnet_dev_dt_node_t *
vnet_dev_dt_deref_node (vnet_dev_dt_node_t *n, char *name)
{
  vnet_dev_dt_main_t *dm = &vnet_dev_dt_main;
  vnet_dev_dt_property_t *p;
  uword *h;

  p = vnet_dev_dt_get_node_property_by_name (n, name);
  if (!p || (p->size != sizeof (u32)))
    return 0;

  h = hash_get (dm->node_by_phandle, clib_net_to_host_u32 (*(u32u *) p->data));

  if (h)
    return (vnet_dev_dt_node_t *) h[0];

  return 0;
}

static u8 *
format_dev_platform_device_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  return format (s, "device-tree path is '%v'", dd->node->path);
}

static u8 *
format_dev_platform_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  return format (s, "%s", dev->device_id + sizeof (PLATFORM_BUS_NAME));
}

VNET_DEV_REGISTER_BUS (pp2) = {
  .name = PLATFORM_BUS_NAME,
  .device_data_size = sizeof (vnet_dev_bus_platform_device_info_t),
  .ops = {
    .get_device_info = vnet_dev_dt_get_device_info,
    .free_device_info = vnet_dev_dt_free_device_info,
    .device_open = vnet_dev_dt_open,
    .device_close = vnet_dev_dt_close,
    .format_device_info = format_dev_platform_device_info,
    .format_device_addr = format_dev_platform_device_addr,
  },
};
