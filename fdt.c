#if 0
cc \
  -g \
  -march=native \
  -O0 \
  -Isrc \
  -Llib/$(uname -m)-linux-gnu \
  -Wl,-rpath ./lib/$(uname -m)-linux-gnu \
  "$0" \
  -lvppinfra \
  && exec ./a.out "$@"
exit
#endif

#define _GNU_SOURCE
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/unix.h>
#include <vppinfra/time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

void *
fdt_property_get_data (vnet_bus_dt_property_t *p)
{
  return p->data;
}

static_always_inline vnet_bus_dt_node_t *
foreach_fdt_tree_node_helper (vnet_bus_dt_node_t *first,
			      vnet_bus_dt_node_t **prev, vnet_bus_dt_node_t *n)
{
  vnet_bus_dt_node_t *next;

again:
  if ((!*prev || (*prev)->parent != n) && vec_len (n->child_nodes) > 0)
    next = n->child_nodes[0];
  else if (n->next)
    next = n->next;
  else
    {
      next = n->parent;
      *prev = n;
      n = next;
      if (n == first)
	return 0;
      goto again;
    }

  *prev = n;
  return next == first ? 0 : next;
}

#define foreach_fdt_tree_node(_n, _first)                                     \
  for (vnet_bus_dt_node_t *__last = 0, *(_n) = _first; _n;                    \
       _n = foreach_fdt_tree_node_helper (_first, &__last, _n))

__clib_export u8 *
format_fdt_tree (u8 *s, va_list *args)
{
  fdt_main_t *fm = va_arg (*args, fdt_main_t *);

  foreach_fdt_tree_node (n, fm->nodes[0])
    {
      s = format (s, "\n%U%v [node: %s]", format_white_space, n->depth * 0,
		  n->path, fdt_property_get_data (n->name));

      vec_foreach_pointer (p, n->properties)
	s = format (s, "\n%U", format_fdt_property, p);
    }

  return s;
}

int
main ()
{

  clib_mem_init (0, 64 << 20);
  fdt_main_t *fm;
  clib_time_t t;
  f64 t0, t1;

  clib_time_init (&t);

  t0 = clib_time_now (&t);
  fm = fdt_read_from_sysfs ();
  t1 = clib_time_now (&t);

  fformat (stdout, "time: %.9f\ntree: %U\n", t1 - t0, format_fdt_tree, fm);

  fdt_main_free (fm);
  return 0;
}
