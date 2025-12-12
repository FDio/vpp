/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018, Microsoft Corporation.
 */

#include <vlib/vlib.h>
#include <vlib/vmbus/vmbus.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* this is a stub replaced by the Linux specfic version */
vlib_vmbus_addr_t *__clib_weak
vlib_vmbus_get_all_dev_addrs ()
{
  return NULL;
}

u8 *__clib_weak
format_vlib_vmbus_addr (u8 *s, va_list *va)
{
  return 0;
}

uword __clib_weak
unformat_vlib_vmbus_addr (unformat_input_t *input, va_list *args)
{
  return 0;
}

clib_error_t *
vmbus_bus_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vmbus_bus_init);
