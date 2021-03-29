VPP_EXTRA_CMAKE_ARGS="-DVPP_ENABLE_FUZZER=ON"


add a chunk of code similar to below:


static int
fuzz_driver_acl_add_replace(const void *data, uword count)
{
    vl_api_acl_add_replace_t_handler((void *)data);
    return 0;
}

extern int vpp_fuzzer_run_driver(int *argc, char ***argv,
                  int (*UserCb)(const void *Data, uword Size));


static char *args[] = { "/tmp/fuzzer", 0 };


static clib_error_t *
acl_fuzz_aclplugin_fn (vlib_main_t * vm,
                        unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  clib_warning("fuzzing...");
  int argc = 1;
  char **argv = args;
  vpp_fuzzer_run_driver(&argc, &argv, fuzz_driver_acl_add_replace);
  return error;
}



VLIB_CLI_COMMAND (aclplugin_fuzz_command, static) = {
    .path = "acl-plugin fuzz-test",
    .short_help = "do some fuzzing",
    .function = acl_fuzz_aclplugin_fn,
};





"make build"

    LD_LIBRARY_PATH=${HOME}/vpp/build-root/install-vpp_debug-native/vpp/lib/ ${HOME}/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp  "unix { interactive cli-listen /tmp/vpp-api-cli.sock } plugins { plugin dpdk_plugin.so { disable } } socksvr { socket-name /tmp/api.sock }"

