#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <plugins/acl/exports.h>



static u32 calico_acl_user_id;
static acl_plugin_methods_t acl_plugin;


static clib_error_t *
calpol_init (vlib_main_t * vm)
{
  clib_error_t *acl_init_res = acl_plugin_exports_init (&acl_plugin);
  if (acl_init_res)
    return (acl_init_res);

  calico_acl_user_id =
    acl_plugin.register_user_module ("Calico Policy Plugin", NULL, NULL);

  return (NULL);
}

static clib_error_t *
calpol_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
	return NULL;
}


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Calico Policy",
};
/* *INDENT-ON* */


VLIB_CONFIG_FUNCTION (calpol_plugin_config, "calico-policy-plugin");

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (calpol_init) =
{
  .runs_after = VLIB_INITS("acl_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

