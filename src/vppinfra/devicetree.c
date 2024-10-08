/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <vppinfra/devicetree.h>

#ifdef __linux
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

static_always_inline clib_dt_node_t *
clib_dt_node_add_child (clib_dt_main_t *dm, clib_dt_node_t *n, char *name)
{
  clib_dt_node_t *cn;

  cn = clib_mem_alloc (sizeof (clib_dt_node_t));
  *cn = (clib_dt_node_t){ .parent = n, .depth = n ? n->depth + 1 : 0 };
  vec_add1 (dm->nodes, cn);

  if (n == 0)
    {
      ASSERT (dm->root == 0);
      dm->root = cn;
      return cn;
    }

  vec_add1 (n->child_nodes, cn);
  cn->path = format (0, "%v/%s", n->path, name);
  cn->dt_main = dm;
  hash_set_mem (dm->node_by_path, cn->path, cn);
  if (vec_len (n->child_nodes) > 1)
    {
      clib_dt_node_t *prev = n->child_nodes[vec_len (n->child_nodes) - 2];
      prev->next = cn;
      cn->prev = prev;
    }

  return cn;
}
#endif

void
clib_dt_main_free (clib_dt_main_t *dm)
{
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
  hash_free (dm->node_by_phandle);
}

#ifdef __linux
__clib_export clib_error_t *
clib_dt_read_from_sysfs (clib_dt_main_t *dm)
{
  DIR *dir, **dir_stack = 0;
  struct dirent *e;
  clib_dt_node_t *n;
  u8 *path = 0;
  u32 path_prefix_len;
  clib_error_t *err = 0;

  path = format (0, CLIB_DT_LINUX_PREFIX);
  path_prefix_len = vec_len (path);
  vec_add1 (path, 0);

  dir = opendir ((char *) path);
  if (!dir)
    {
      err = clib_error_return (0, "'%s' opendir failed", path);
      goto done;
    }

  dm->node_by_path = hash_create_vec (0, sizeof (u8), sizeof (uword));
  dm->node_by_phandle = hash_create (0, sizeof (uword));
  vec_set_len (path, path_prefix_len);
  n = clib_dt_node_add_child (dm, 0, 0);

  while (1)
    {
      e = readdir (dir);

      if (!e)
	{
	  closedir (dir);
	  if (vec_len (dir_stack) == 0)
	    break;

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
		  u32 sz = sizeof (clib_dt_property_t) + st.st_size;
		  clib_dt_property_t *p = clib_mem_alloc (sz);
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
		      err = clib_error_return (0, "'%s' read failed", path);
		      close (fd);
		      goto done;
		    }
		}
	      else
		{
		  err = clib_error_return (0, "'%s' fstat failed", path);
		  close (fd);
		  goto done;
		}
	      close (fd);
	    }
	  else
	    {
	      err = clib_error_return (0, "'%s' open failed", path);
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
	      n = clib_dt_node_add_child (dm, n, e->d_name);
	    }
	  else
	    {
	      err = clib_error_return (0, "'%s' opendir failed", path);
	      goto done;
	    }
	}
      else
	err =
	  clib_error_return (0, "unknown entry %s [%u]", e->d_name, e->d_type);
    }

done:
  if (err)
    clib_dt_main_free (dm);
  while (vec_len (dir_stack))
    closedir (vec_pop (dir_stack));
  vec_free (dir_stack);
  vec_free (path);
  return err;
}
#endif

__clib_export clib_dt_node_t *
clib_dt_get_child_node (clib_dt_node_t *n, char *fmt, ...)
{
  u8 *s;
  va_list va;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (s, 0);

  vec_foreach_pointer (cn, n->child_nodes)
    {
      u8 *p = cn->path + vec_len (cn->path) - 1;
      u32 i = 0;

      while (p > cn->path && p[-1] != '/')
	p--;

      if (p[-1] != '/')
	continue;

      while (p[i] == s[i] && s[i] != 0)
	i++;

      if (s[i] != 0)
	continue;

      vec_free (s);
      return cn;
    }

  vec_free (s);
  return 0;
}

__clib_export clib_dt_node_t *
clib_dt_get_node_with_path (clib_dt_main_t *dm, char *fmt, ...)
{
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
    return (clib_dt_node_t *) p[0];

  return 0;
}

__clib_export clib_dt_property_t *
clib_dt_get_node_property_by_name (clib_dt_node_t *n, char *name)
{
  vec_foreach_pointer (p, n->properties)
    if (strncmp (name, p->name, sizeof (p->name)) == 0)
      return p;
  return 0;
}

__clib_export int
clib_dt_node_is_compatible (clib_dt_node_t *n, char *comp)
{
  clib_dt_property_t *p;
  char *s;

  p = clib_dt_get_node_property_by_name (n, "compatible");

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

__clib_export u8 *
format_clib_dt_property_data (u8 *s, va_list *args)
{
  clib_dt_property_t *p = va_arg (*args, clib_dt_property_t *);
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

__clib_export clib_dt_node_t *
clib_dt_dereference_node (clib_dt_node_t *n, char *name)
{
  clib_dt_property_t *p;
  uword *h;

  p = clib_dt_get_node_property_by_name (n, name);
  if (!p || (p->size != sizeof (u32)))
    return 0;

  h = hash_get (n->dt_main->node_by_phandle,
		clib_net_to_host_u32 (*(u32u *) p->data));

  if (h)
    return (clib_dt_node_t *) h[0];

  return 0;
}
