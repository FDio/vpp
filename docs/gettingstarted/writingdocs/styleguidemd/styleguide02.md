Bullets, Bold and Italics
=========================

Bold text can be show with **Bold Text**, Italics with *Italic text*.
Bullets like so:

-   Bullet 1
-   Bullet 2

Code Blocks
===========

This paragraph describes how to do **Console Commands**. When showing
VPP commands it is reccomended that the command be executed from the
linux console as shown. The Highlighting in the final documents shows up
nicely this way.

``` console
$ sudo bash
# vppctl show interface
              Name               Idx       State          Counter          Count     
TenGigabitEthernet86/0/0          1         up       rx packets               6569213
                                                     rx bytes              9928352943
                                                     tx packets                 50384
                                                     tx bytes                 3329279
TenGigabitEthernet86/0/1          2        down      
VirtualEthernet0/0/0              3         up       rx packets                 50384
                                                     rx bytes                 3329279
                                                     tx packets               6569213
                                                     tx bytes              9928352943
                                                     drops                       1498
local0                            0        down      
#
```

The **code-block** construct is also used for code samples. The
following shows how to include a block of \"C\" code.

``` c
#include <vlib/unix/unix.h>
abf_policy_t *
abf_policy_get (u32 index)
{
  return (pool_elt_at_index (abf_policy_pool, index));
}
```

Diffs are generated in the final docs nicely with \":\" at the end of
the description like so:

    diff --git a/src/vpp/vnet/main.c b/src/vpp/vnet/main.c
    index 6e136e19..69189c93 100644
    --- a/src/vpp/vnet/main.c
    +++ b/src/vpp/vnet/main.c
    @@ -18,6 +18,8 @@
     #include <vlib/unix/unix.h>
     #include <vnet/plugin/plugin.h>
     #include <vnet/ethernet/ethernet.h>
    +#include <vnet/ip/ip4_packet.h>
    +#include <vnet/ip/format.h>
     #include <vpp/app/version.h>
     #include <vpp/api/vpe_msg_enum.h>
     #include <limits.h>
    @@ -400,6 +402,63 @@ VLIB_CLI_COMMAND (test_crash_command, static) = {

     #endif
