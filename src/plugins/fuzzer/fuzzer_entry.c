#include <vppinfra/types.h>
#include <stdio.h>


static char *args[] = { "/tmp/fuzzer", 0 };

extern int fuzzer_lib_main(int argc, char **argv);

static int (*user_callback)(const void *Data, uword Size) = 0;


__attribute__ ((visibility ("default"))) int vpp_fuzzer_run_driver(int *argc, char ***argv,
                  int (*UserCb)(const void *Data, uword Size)) {
    user_callback = UserCb;
    fprintf(stderr, "fuzzer callback set to %p\n", user_callback);
    fuzzer_lib_main(1, args);
    user_callback = 0;
    return 0;
}

int LLVMFuzzerTestOneInput(const void *ptr, uword len) {
	if (user_callback) {
		return user_callback(ptr, len);
	}
        return 0;
}


