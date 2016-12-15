/* this file is never compiled, it is used by helper build script */

int pneum_get_map(int count, unsigned long *values, const char **keys);
int wrap_pneum_connect(char *name, char *chroot_prefix);
int wrap_pneum_connect_async(char *name, char *chroot_prefix);
extern "Python" void global_msg_handler(char * data, int len);
extern "Python" void global_async_msg_handler(char * data, int len);
