#include <vppinfra/time.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vpp/stats/stat_segment.h>
#include <vpp-api/client/stat_client.h>
#include <vppinfra/vec.h>
#include <mactime/mactime_device.h>
#include <vlibapi/api_common.h>
#include <vlibmemory/memory_client.h>
#include <vlibmemory/api.h>
#include <vnet/api_errno.h>
#include <svm/queue.h>

/* define message IDs */
#include <mactime/mactime.api_enum.h>
#include <mactime/mactime.api_types.h>

typedef struct
{
  /* device database */
  uword *device_by_device_name;
  mactime_device_t *devices;
  u32 my_table_epoch;

  /* Stat segment variables */
  stat_client_main_t *stat_client_main;
  u8 **pattern1, **pattern2;
  u32 *ls_result1, *ls_result2;
  vlib_counter_t *allow_counters;
  vlib_counter_t *drop_counters;

  /* Timebase */
  clib_time_t clib_time;
  clib_timebase_t timebase;
  f64 timezone_offset;
  f64 sunday_midnight;

  /* API message-handling */
  svm_queue_t *vl_input_queue;
  u32 my_client_index;
  u16 msg_id_base;
  volatile u32 result_ready;
  volatile i32 retval;
} mt_main_t;

mt_main_t mt_main;

/* Indispensable for debugging in gdb... */

u32
vl (void *x)
{
  return vec_len (x);
}

#define foreach_mactime_api_msg                 \
_(MACTIME_DUMP_REPLY, mactime_dump_reply)       \
_(MACTIME_DETAILS, mactime_details)

static void vl_api_mactime_dump_reply_t_handler
  (vl_api_mactime_dump_reply_t * mp)
{
  mt_main_t *mm = &mt_main;
  i32 retval = clib_net_to_host_u32 (mp->retval);

  mm->retval = retval;
  mm->result_ready = 1;
}

static void
vl_api_mactime_details_t_handler (vl_api_mactime_details_t * mp)
{
  mt_main_t *mm = &mt_main;
  mactime_device_t *dev;
  int i;
  clib_timebase_range_t *rp;
  uword *p;

  if (PREDICT_FALSE (mm->device_by_device_name == 0))
    mm->device_by_device_name = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (mm->device_by_device_name, mp->device_name);
  if (p)
    dev = pool_elt_at_index (mm->devices, p[0]);
  else
    {
      u8 *hash_name_copy = format (0, "%s%c", mp->device_name, 0);
      pool_get (mm->devices, dev);
      memset (dev, 0, sizeof (*dev));
      dev->device_name = vec_dup (hash_name_copy);
      hash_set_mem (mm->device_by_device_name, hash_name_copy,
		    dev - mm->devices);
    }

  clib_memcpy_fast (dev->mac_address, mp->mac_address,
		    sizeof (dev->mac_address));
  dev->data_quota = clib_net_to_host_u64 (mp->data_quota);
  dev->data_used_in_range = clib_net_to_host_u64 (mp->data_used_in_range);
  dev->flags = clib_net_to_host_u32 (mp->flags);
  dev->pool_index = clib_net_to_host_u32 (mp->pool_index);
  vec_reset_length (dev->ranges);
  for (i = 0; i < clib_net_to_host_u32 (mp->nranges); i++)
    {
      vec_add2 (dev->ranges, rp, 1);
      rp->start = mp->ranges[i].start;
      rp->end = mp->ranges[i].end;
    }
}

#define vl_print(handle, ...) fformat(handle, __VA_ARGS__)

#define vl_endianfun
#define vl_printfun
#define vl_api_version(n,v) static u32 api_version = v;
#include <mactime/mactime.api.h>
#undef vl_api_version
#undef vl_printfun
#undef vl_endianfun

static int
connect_to_vpp (char *name)
{
  api_main_t *am = vlibapi_get_main ();
  mt_main_t *mm = &mt_main;
  u8 *msg_base_lookup_name;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  mm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  mm->my_client_index = am->my_client_index;

  msg_base_lookup_name = format (0, "mactime_%08x%c", api_version, 0);

  mm->msg_id_base = vl_client_get_first_plugin_msg_id
    ((char *) msg_base_lookup_name);

  vec_free (msg_base_lookup_name);

  if (mm->msg_id_base == ~0)
    return -1;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_mactime_api_msg;
#undef _

  return 0;
}

static void
dump_mactime_table (mt_main_t * mm)
{
  vl_api_mactime_dump_t *mp;
  u32 deadman_counter = 1000;

  /* Send the dump request */
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_MACTIME_DUMP + mm->msg_id_base);
  mp->client_index = mm->my_client_index;
  mp->my_table_epoch = mm->my_table_epoch;
  vl_msg_api_send_shmem (mm->vl_input_queue, (u8 *) & mp);

  /* Wait up to 1 second for vpp to reply */
  while (deadman_counter-- && mm->result_ready == 0)
    unix_sleep (1e-3);

  if (mm->retval && (mm->retval != VNET_API_ERROR_NO_CHANGE))
    clib_warning ("dump reply %d", mm->retval);

}

static void
scrape_stats_segment (mt_main_t * mm)
{
  vlib_counter_t **counters_by_thread;
  vlib_counter_t *counters;
  u64 *offset_vector;
  mactime_device_t *dev;
  stat_segment_access_t sa;
  stat_client_main_t *sm = mm->stat_client_main;
  stat_segment_directory_entry_t *ep;
  int need_update2 = 0;
  static u32 *pool_indices;
  int i, j;

  vec_reset_length (pool_indices);
  /* *INDENT-OFF* */
  pool_foreach (dev, mm->devices,
  ({
    vec_add1 (pool_indices, dev->pool_index);
  }));
  /* *INDENT-ON* */

  /* Nothing to do... */
  if (vec_len (pool_indices) == 0)
    return;

again1:

  /* Has directory been updated? */
  if (mm->ls_result1 == 0 || (sm->shared_header->epoch != sm->current_epoch))
    {
      need_update2 = 1;
      vec_free (mm->ls_result1);
      mm->ls_result1 = stat_segment_ls (mm->pattern1);
    }

  stat_segment_access_start (&sa, sm);

  ep = vec_elt_at_index (sm->directory_vector, mm->ls_result1[0]);
  counters_by_thread = stat_segment_pointer (sm->shared_header, ep->offset);
  offset_vector = stat_segment_pointer (sm->shared_header, ep->offset_vector);

  for (i = 0; i < vec_len (pool_indices); i++)
    {
      u32 index = pool_indices[i];

      vec_validate (mm->allow_counters, index);
      mm->allow_counters[index].packets = 0;
      mm->allow_counters[index].bytes = 0;

      for (j = 0; j < vec_len (counters_by_thread); j++)
	{
	  counters = stat_segment_pointer (sm->shared_header,
					   offset_vector[j]);
	  mm->allow_counters[index].packets += counters[index].packets;
	  mm->allow_counters[index].bytes += counters[index].bytes;
	}
    }

  /* Ugh, segment changed during access. Try again */
  if (stat_segment_access_end (&sa, sm))
    goto again1;

  /* Has directory been updated? */
  if (mm->ls_result2 == 0 || need_update2)
    {
      vec_free (mm->ls_result2);
      mm->ls_result2 = stat_segment_ls (mm->pattern2);
    }

again2:
  stat_segment_access_start (&sa, sm);

  ep = vec_elt_at_index (sm->directory_vector, mm->ls_result2[0]);
  counters_by_thread = stat_segment_pointer (sm->shared_header, ep->offset);
  offset_vector = stat_segment_pointer (sm->shared_header, ep->offset_vector);

  for (i = 0; i < vec_len (pool_indices); i++)
    {
      u32 index = pool_indices[i];

      vec_validate (mm->drop_counters, index);
      mm->drop_counters[index].packets = 0;
      mm->drop_counters[index].bytes = 0;

      for (j = 0; j < vec_len (counters_by_thread); j++)
	{
	  counters = stat_segment_pointer (sm->shared_header,
					   offset_vector[j]);
	  mm->drop_counters[index].packets += counters[index].packets;
	  mm->drop_counters[index].bytes += counters[index].bytes;
	}
    }
  /* Ugh, segment changed during access. Try again */
  if (stat_segment_access_end (&sa, sm))
    goto again2;
}

static u8 *
format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

static u8 *
format_bytes_with_width (u8 * s, va_list * va)
{
  uword nbytes = va_arg (*va, u64);
  int width = va_arg (*va, int);
  f64 nbytes_f64;
  u8 *fmt;
  char *suffix = "";

  if (width > 0)
    fmt = format (0, "%%%d.3f%%s%c", width, 0);
  else
    fmt = format (0, "%%.3f%%s%c", 0);

  if (nbytes > (1024ULL * 1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0 * 1024.0);
      suffix = "G";
    }
  else if (nbytes > (1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0);
      suffix = "M";
    }
  else if (nbytes > 1024ULL)
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0);
      suffix = "K";
    }
  else
    {
      nbytes_f64 = (f64) nbytes;
      suffix = "B";
    }

  s = format (s, (char *) fmt, nbytes_f64, suffix);
  vec_free (fmt);
  return s;
}

static u8 *
format_device (u8 * s, va_list * args)
{
  mactime_device_t *dp = va_arg (*args, mactime_device_t *);
  mt_main_t *mm = &mt_main;
  int verbose = va_arg (*args, int);
  int current_status = 99;
  char *status_string;
  u8 *macstring = 0;
  f64 now;
  int j;

  if (dp == 0)
    {
      s = format (s, "%-15s %5s %18s %14s %10s %11s %13s",
		  "Device Name", "Index", "Addresses", "Status",
		  "AllowPkt", "AllowByte", "DropPkt");
      vec_add1 (s, '\n');
      return s;
    }

  now = clib_timebase_now (&mm->timebase);

  if (PREDICT_FALSE ((now - mm->sunday_midnight) > 86400.0 * 7.0))
    mm->sunday_midnight = clib_timebase_find_sunday_midnight (now);

  /* Check dynamic ranges */
  for (j = 0; j < vec_len (dp->ranges); j++)
    {
      clib_timebase_range_t *r = dp->ranges + j;
      f64 start0, end0;

      start0 = r->start + mm->sunday_midnight;
      end0 = r->end + mm->sunday_midnight;
      if (verbose)
	s = format (s, "  Range %d: %U - %U\n", j,
		    format_clib_timebase_time, start0,
		    format_clib_timebase_time, end0);

      if (now >= start0 && now <= end0)
	{
	  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
	    current_status = 3;
	  else if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
	    current_status = 5;
	  else
	    current_status = 2;
	  if (verbose)
	    {
	      s = format (s, "  Time in range %d:", j);
	      s = format (s, "     %U - %U\n",
			  format_clib_timebase_time, start0,
			  format_clib_timebase_time, end0);
	    }
	  goto print;
	}
    }
  if (verbose && j)
    s = format (s, "  No range match.\n");
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
  macstring = format (0, "%U", format_mac_address, dp->mac_address);
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

  s = format (s, "%-15s %5d %18s %14s %10lld %U %13lld\n",
	      dp->device_name, dp->pool_index, macstring, status_string,
	      mm->allow_counters[dp->pool_index].packets,
	      format_bytes_with_width,
	      mm->allow_counters[dp->pool_index].bytes, 10,
	      mm->drop_counters[dp->pool_index].packets);
  vec_free (macstring);

  if (dp->data_quota > 0)
    {
      s = format (s, "%-59s %s%U %s%U", " ", "Quota ",
		  format_bytes_with_width, dp->data_quota, 10,
		  "Use ", format_bytes_with_width, dp->data_used_in_range, 8);
      vec_add1 (s, '\n');
    }
  return s;
}

static void
print_device_table (mt_main_t * mm)
{
  mactime_device_t *dev;

  fformat (stdout, "%U", format_device, NULL /* header */ , 0 /* verbose */ );
  /* *INDENT-OFF* */
  pool_foreach (dev, mm->devices,
  ({
    fformat (stdout, "%U", format_device, dev, 0 /* verbose */);
  }));
  /* *INDENT-ON* */
}

int
main (int argc, char **argv)
{
  mt_main_t *mm = &mt_main;
  extern stat_client_main_t stat_client_main;

  clib_mem_init (0, 64 << 20);

  if (connect_to_vpp ("mactime_top") < 0)
    {
      fformat (stderr, "vpp api client connect error\n");
      exit (1);
    }

  if (stat_segment_connect (argv[1]) < 0)
    {
      fformat (stderr, "stat segment connect error");
      exit (1);
    }

  mm->stat_client_main = (stat_client_main_t *) & stat_client_main;

  /* US EDT - $$$ FIXME */
  clib_time_init (&mm->clib_time);
  mm->timezone_offset = -5.0;
  clib_timebase_init (&mm->timebase, mm->timezone_offset,
		      CLIB_TIMEBASE_DAYLIGHT_USA,
		      0 /* allocate a clib_time_t */ );

  vec_add1 (mm->pattern1, (u8 *) "^/mactime/allow");
  vec_add1 (mm->pattern2, (u8 *) "^/mactime/drop");

  while (1)
    {
      dump_mactime_table (mm);
      scrape_stats_segment (mm);
      print_device_table (mm);
      unix_sleep (5.0);
    }
  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
