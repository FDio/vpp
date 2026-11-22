#include "vat.h"
#include <dlfcn.h>
#include <vat/plugin.h>

vat_main_t vat_main;

void __clib_no_tail_calls
vat_suspend (vlib_main_t *vm, f64 interval)
{
  vlib_process_suspend (vm, interval);
}

static void
init_error_string_table (vat_main_t * vam)
{

  vam->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (vam->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vam->error_string_by_error_number, 99, "Misc");
}

#if VPP_API_TEST_BUILTIN > 0
static void
load_features (void)
{
  vat_registered_features_t *f;
  vat_main_t *vam = &vat_main;
  clib_error_t *error;

  f = vam->feature_function_registrations;

  while (f)
    {
      error = f->function (vam);
      if (error)
	{
	  clib_warning ("INIT FAILED");
	}
      f = f->next;
    }
}

clib_error_t *
vat_builtin_main_init (vlib_main_t * vm)
{
  vat_main_t *vam = &vat_main;
  int rv;
  int vat_plugin_init (vat_main_t * vam);

  vam->vlib_main = vm;
  vam->my_client_index = (u32) ~ 0;
  /* Ensure that vam->inbuf is never NULL */
  vec_validate (vam->inbuf, 0);
  vec_validate (vam->cmd_reply, 0);
  vec_reset_length (vam->cmd_reply);
  init_error_string_table (vam);
  rv = vat_plugin_init (vam);
  if (rv)
    clib_warning ("vat_plugin_init returned %d", rv);

  load_features ();

  return 0;
}
#endif

void
vat_plugin_hash_create (void)
{
  vat_main_t *vam = &vat_main;

  vam->sw_if_index_by_interface_name = hash_create_string (0, sizeof (uword));
  vam->function_by_name = hash_create_string (0, sizeof (uword));
  vam->help_by_name = hash_create_string (0, sizeof (uword));
}

void
api_cli_output (void *notused, const char *fmt, ...)
{
  va_list va;
  vat_main_t *vam = &vat_main;
  vlib_main_t *vm = vam->vlib_main;
  vlib_process_t *cp = vlib_get_current_process (vm);
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  /* Terminate with \n if not present. */
  if (vec_len (s) > 0 && s[vec_len (s) - 1] != '\n')
    vec_add1 (s, '\n');

  if ((!cp) || (!cp->output_function))
    fformat (stdout, "%v", s);
  else
    cp->output_function (cp->output_function_arg, s, vec_len (s));

  vec_free (s);
}

u16
vl_client_get_first_plugin_msg_id (const char *plugin_name)
{
  api_main_t *am = vlibapi_get_main ();
  vl_api_msg_range_t *rp;
  uword *p;

  p = hash_get_mem (am->msg_range_by_name, plugin_name);
  if (p == 0)
    return ~0;

  rp = vec_elt_at_index (am->msg_ranges, p[0]);

  return (rp->first_msg_id);
}

uword
unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  void *vam_unused = va_arg (*args, void *);
  (void) (vam_unused);
  u32 *result = va_arg (*args, u32 *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;

  if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      *result = sw_if_index;
      return 1;
    }
  return 0;
}
