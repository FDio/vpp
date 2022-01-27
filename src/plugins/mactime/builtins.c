#include <vnet/vnet.h>
#include <builtinurl/builtinurl.h>
#include <http_static/http_static.h>
#include <mactime/mactime.h>
#include <vlib/unix/plugin.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

static walk_rc_t
mactime_ip_neighbor_copy (index_t ipni, void *ctx)
{
  mactime_main_t *mm = ctx;

  vec_add1 (mm->arp_cache_copy, ipni);

  return (WALK_CONTINUE);
}

static int
handle_get_mactime (http_builtin_method_type_t reqtype, u8 *request,
		    hss_session_t *hs)
{
  mactime_main_t *mm = &mactime_main;
  mactime_device_t *dp;
  u8 *macstring = 0;
  char *status_string;
  u32 *pool_indices = 0;
  int current_status = 99;
  int i, j;
  f64 now;
  vlib_counter_t allow, drop;
  ip_neighbor_t *n;
  char *q = "\"";
  u8 *s = 0;
  int need_comma = 0;

  /* Walk all ip4 neighbours on all interfaces */
  vec_reset_length (mm->arp_cache_copy);
  ip_neighbor_walk (AF_IP4, ~0, mactime_ip_neighbor_copy, mm);

  now = clib_timebase_now (&mm->timebase);

  if (PREDICT_FALSE ((now - mm->sunday_midnight) > 86400.0 * 7.0))
    mm->sunday_midnight = clib_timebase_find_sunday_midnight (now);

  pool_foreach (dp, mm->devices)
    {
      vec_add1 (pool_indices, dp - mm->devices);
    }

  s = format (s, "{%smactime%s: [\n", q, q);

  for (i = 0; i < vec_len (pool_indices); i++)
    {
      dp = pool_elt_at_index (mm->devices, pool_indices[i]);

      /* Check dynamic ranges */
      for (j = 0; j < vec_len (dp->ranges); j++)
	{
	  clib_timebase_range_t *r = dp->ranges + j;
	  f64 start0, end0;

	  start0 = r->start + mm->sunday_midnight;
	  end0 = r->end + mm->sunday_midnight;

	  if (now >= start0 && now <= end0)
	    {
	      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
		current_status = 3;
	      else if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
		current_status = 5;
	      else
		current_status = 2;
	      goto print;
	    }
	}
      if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_DROP)
	current_status = 0;
      if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_ALLOW)
	current_status = 1;
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
	current_status = 2;
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_DROP)
	current_status = 3;
      if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
	current_status = 4;

    print:
      vec_reset_length (macstring);

      macstring = format (0, "%U", format_mac_address, dp->mac_address);

      if (need_comma)
	s = format (s, "},\n");

      need_comma = 1;
      s = format (s, "{%smac_address%s: %s%s%s, ", q, q, q, macstring, q);

      switch (current_status)
	{
	case 0:
	  status_string = "static drop";
	  break;
	case 1:
	  status_string = "static allow";
	  break;
	case 2:
	  status_string = "dynamic drop";
	  break;
	case 3:
	  status_string = "dynamic allow";
	  break;
	case 4:
	  status_string = "d-quota inact";
	  break;
	case 5:
	  status_string = "d-quota activ";
	  break;
	default:
	  status_string = "code bug!";
	  break;
	}
      vlib_get_combined_counter (&mm->allow_counters, dp - mm->devices,
				 &allow);
      vlib_get_combined_counter (&mm->drop_counters, dp - mm->devices, &drop);
      s = format (s, "%sname%s: %s%s%s, %sstatus%s: %s%s%s,",
		  q, q, q, dp->device_name, q, q, q, q, status_string, q);
      s = format (s, "%sallow_pkts%s: %lld,", q, q, allow.packets);
      s = format (s, "%sallow_bytes%s: %lld,", q, q, allow.bytes);
      s = format (s, "%sdrop_pkts%s: %lld", q, q, drop.packets);

      for (j = 0; j < vec_len (mm->arp_cache_copy); j++)
	{
	  n = ip_neighbor_get (mm->arp_cache_copy[j]);
	  if (!memcmp (dp->mac_address,
		       ip_neighbor_get_mac (n), sizeof (mac_address_t)))
	    {
	      s = format (s, ", %sip4_address%s: %s%U%s", q, q,
			  q, format_ip46_address,
			  ip_neighbor_get_ip (n), IP46_TYPE_IP4, q);
	      break;
	    }
	}
    }
  if (need_comma)
    s = format (s, "}\n");
  s = format (s, "]}\n");
  vec_free (macstring);
  vec_free (pool_indices);

  hs->data = s;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;
  hs->free_data = 1;
  return 0;
}

void
mactime_url_init (vlib_main_t * vm)
{
  void (*fp) (void *, char *, int);

  /* Look up the builtin URL registration handler */
  fp = vlib_get_plugin_symbol ("http_static_plugin.so",
			       "http_static_server_register_builtin_handler");

  if (fp == 0)
    {
      clib_warning ("http_static_plugin.so not loaded...");
      return;
    }

  (*fp) (handle_get_mactime, "mactime.json", HTTP_BUILTIN_METHOD_GET);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
