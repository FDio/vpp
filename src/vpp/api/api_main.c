#include "vat.h"

vat_main_t vat_main;

void
vat_suspend (vlib_main_t * vm, f64 interval)
{
  vlib_process_suspend (vm, interval);
}

static u8 *
format_api_error (u8 * s, va_list * args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (vam->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
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

static clib_error_t *
api_main_init (vlib_main_t * vm)
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

  return 0;
}

VLIB_INIT_FUNCTION (api_main_init);

void
vat_plugin_hash_create (void)
{
  vat_main_t *vam = &vat_main;

  vam->sw_if_index_by_interface_name = hash_create_string (0, sizeof (uword));
  vam->function_by_name = hash_create_string (0, sizeof (uword));
  vam->help_by_name = hash_create_string (0, sizeof (uword));
}

static void
maybe_register_api_client (vat_main_t * vam)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  svm_region_t *svm;
  void *oldheap;
  api_main_t *am = &api_main;

  if (vam->my_client_index != ~0)
    return;

  pool_get (am->vl_clients, regpp);

  svm = am->vlib_rp;

  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));

  regp = *regpp;
  memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;
  regp->vlib_rp = svm;
  regp->shmem_hdr = am->shmem_hdr;

  /* Loopback connection */
  regp->vl_input_queue = am->shmem_hdr->vl_input_queue;

  regp->name = format (0, "%s", "vpp-internal");
  vec_add1 (regp->name, 0);

  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);

  vam->my_client_index = vl_msg_api_handle_from_index_and_epoch
    (regp->vl_api_registration_pool_index,
     am->shmem_hdr->application_restarts);
}

static clib_error_t *
api_command_fn (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vat_main_t *vam = &vat_main;
  unformat_input_t _input;
  uword c;
  u8 *cmdp, *argsp, *this_cmd;
  uword *p;
  u32 arg_len;
  int rv;
  int (*fp) (vat_main_t *);
  api_main_t *am = &api_main;

  maybe_register_api_client (vam);

  vam->vl_input_queue = am->shmem_hdr->vl_input_queue;

  /* vec_validated in the init routine */
  _vec_len (vam->inbuf) = 0;

  vam->input = &_input;

  while (((c = unformat_get_input (input)) != '\n') &&
	 (c != UNFORMAT_END_OF_INPUT))
    vec_add1 (vam->inbuf, c);

  /* Null-terminate the command */
  vec_add1 (vam->inbuf, 0);

  /* In case no args given */
  vec_add1 (vam->inbuf, 0);

  /* Split input into cmd + args */
  this_cmd = cmdp = vam->inbuf;

  /* Skip leading whitespace */
  while (cmdp < (this_cmd + vec_len (this_cmd)))
    {
      if (*cmdp == ' ' || *cmdp == '\t' || *cmdp == '\n')
	{
	  cmdp++;
	}
      else
	break;
    }

  argsp = cmdp;

  /* Advance past the command */
  while (argsp < (this_cmd + vec_len (this_cmd)))
    {
      if (*argsp != ' ' && *argsp != '\t' && *argsp != '\n' && *argsp != 0)
	{
	  argsp++;
	}
      else
	break;
    }
  /* NULL terminate the command */
  *argsp++ = 0;

  /* No arguments? Ensure that argsp points to a proper (empty) string */
  if (argsp == (this_cmd + vec_len (this_cmd) - 1))
    argsp[0] = 0;
  else
    while (argsp < (this_cmd + vec_len (this_cmd)))
      {
	if (*argsp == ' ' || *argsp == '\t' || *argsp == '\n')
	  {
	    argsp++;
	  }
	else
	  break;
      }

  /* Blank input line? */
  if (*cmdp == 0)
    return 0;

  p = hash_get_mem (vam->function_by_name, cmdp);
  if (p == 0)
    {
      return clib_error_return (0, "'%s': function not found\n", cmdp);
    }

  arg_len = strlen ((char *) argsp);

  unformat_init_string (vam->input, (char *) argsp, arg_len);
  fp = (void *) p[0];

  rv = (*fp) (vam);

  if (rv < 0)
    {
      unformat_free (vam->input);
      return clib_error_return (0,
				"%s error: %U\n", cmdp,
				format_api_error, vam, rv);

    }
  if (vam->regenerate_interface_table)
    {
      vam->regenerate_interface_table = 0;
      api_sw_interface_dump (vam);
    }
  unformat_free (vam->input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (api_command, static) =
{
  .path = "binary-api",
  .short_help = "binary-api [help] <name> [<args>]",
  .function = api_command_fn,
};
/* *INDENT-ON* */

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
  api_main_t *am = &api_main;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
