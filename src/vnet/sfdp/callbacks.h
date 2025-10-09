/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_callbacks_h
#define __included callbacks_h
#include <vlib/vlib.h>

#define foreach_sfdp_callback_type                                            \
  /* Called by sfdp-lookup after new flows have been created but before       \
   * packets have been fully processed.                                       \
   * This gives the opportunity for the SFDP user to initialize               \
   * per-flow state or even modify the service chain before it gets used. */  \
  _ (notify_new_sessions, u32, const u32 *, u32)                              \
  /* Called during pre-input phase to notify that certain flows are being     \
   * removed. This gives the opportunity for the SFDP user to reset per-flow  \
   * state while no packet is currently being processed by this thread.       \
   * This is called before any flow state is removed. */                      \
  _ (notify_deleted_sessions, u32, const u32 *, u32)

#define SFDP_CB_ELT_LIST_TYPE_DECLARE(fn_ptr_type)                            \
  typedef struct sfdp_cb_elt_list_##fn_ptr_type##_s                           \
  {                                                                           \
    struct sfdp_cb_elt_list_##fn_ptr_type##_s *next;                          \
    fn_ptr_type fun;                                                          \
    const char *name;                                                         \
  } sfdp_cb_elt_list_##fn_ptr_type##_t;

#define SFDP_CB_ELT_LIST_TYPE(fn_ptr_type) sfdp_cb_elt_list_##fn_ptr_type##_t

#define SFDP_CALL_CB_ELT(ptr, x...) ((ptr)->fun (x))

#ifndef CLIB_MARCH_VARIANT
#define SFDP_REGISTER_CALLBACK(type, head, name2)                             \
  static SFDP_CB_ELT_LIST_TYPE (type)                                         \
    sfdp_callback_registration_##type_##name2;                                \
  __attribute__ ((__constructor__)) static void                               \
    __sfdp_callback_add_registration_##type_##name2 (void)                    \
                                                                              \
  {                                                                           \
    sfdp_callback_main_t *sfdp = &sfdp_callback_main;                         \
    SFDP_CB_ELT_LIST_TYPE (type) *r =                                         \
      &sfdp_callback_registration_##type_##name2;                             \
    r->next = sfdp->head;                                                     \
    sfdp->head = r;                                                           \
    r->name = #name2;                                                         \
  }                                                                           \
  static SFDP_CB_ELT_LIST_TYPE (type) sfdp_callback_registration_##type_##name2

#define SFDP_BLACKLIST_CALLBACK(type, head, name)                             \
  __attribute__ ((__constructor__)) static void                               \
    __sfdp_callback_blacklist_registration_##type_##name (void)               \
                                                                              \
  {                                                                           \
    sfdp_callback_main_t *sfdp = &sfdp_callback_main;                         \
    vec_add1 (sfdp->blacklist_##head, (const u8 *) #name);                    \
  }
#else
#define SFDP_REGISTER_CALLBACK(type, head, name2)                             \
  static SFDP_CB_ELT_LIST_TYPE (type)                                         \
    __clib_unused sfdp_callback_registration_##type_##name2
#define SFDP_BLACKLIST_CALLBACK(type, head, name)
#endif

#define _(x, y, z...) typedef y (*sfdp_##x##_cb_t) (z);
foreach_sfdp_callback_type
#undef _

#define _(x, ...) SFDP_CB_ELT_LIST_TYPE_DECLARE (sfdp_##x##_cb_t)
  foreach_sfdp_callback_type
#undef _

  typedef struct
{
#define _(x, ...)                                                             \
  SFDP_CB_ELT_LIST_TYPE (sfdp_##x##_cb_t) * head_##x;                         \
  const u8 **blacklist_head_##x;                                              \
  SFDP_CB_ELT_LIST_TYPE (sfdp_##x##_cb_t) * *effective_##x;
  foreach_sfdp_callback_type
#undef _
} sfdp_callback_main_t;

extern sfdp_callback_main_t sfdp_callback_main;

#define SFDP_CALLBACK_BUILD_EFFECTIVE_LIST(x)                                 \
  do                                                                          \
    {                                                                         \
      typeof (sfdp_callback_main.head_##x) hd = sfdp_callback_main.head_##x;  \
      while (hd != 0)                                                         \
	{                                                                     \
	  u8 excluded = 0;                                                    \
	  const u8 **cur;                                                     \
	  vec_foreach (cur, sfdp_callback_main.blacklist_head_##x)            \
	    if (!clib_strncmp ((const char *) cur[0], hd->name, 256))         \
	      excluded = 1;                                                   \
	  if (excluded == 0)                                                  \
	    vec_add1 (sfdp_callback_main.effective_##x, hd);                  \
	  hd = hd->next;                                                      \
	}                                                                     \
    }                                                                         \
  while (0)

#define SFDP_CALLBACKS_CALL(x, y...)                                          \
  do                                                                          \
    {                                                                         \
      typeof (sfdp_callback_main.effective_##x) elt;                          \
      vec_foreach (elt, sfdp_callback_main.effective_##x)                     \
	SFDP_CALL_CB_ELT (elt[0], y);                                         \
    }                                                                         \
  while (0)

/* Per callback type specializations */
#define SFDP_REGISTER_NEW_SESSIONS_CALLBACK(name)                             \
  SFDP_REGISTER_CALLBACK (sfdp_notify_new_sessions_cb_t,                      \
			  head_notify_new_sessions, name)
#define SFDP_BLACKLIST_NEW_SESSIONS_CALLBACK(name)                            \
  SFDP_BLACKLIST_CALLBACK (sfdp_notify_new_sessions_cb_t,                     \
			   head_notify_new_sessions, name)

#define SFDP_REGISTER_DELETED_SESSIONS_CALLBACK(name)                         \
  SFDP_REGISTER_CALLBACK (sfdp_notify_deleted_sessions_cb_t,                  \
			  head_notify_deleted_sessions, name)
#define SFDP_BLACKLIST_DELETED_SESSIONS_CALLBACK(name)                        \
  SFDP_BLACKLIST_CALLBACK (sfdp_notify_deleted_sessions_cb_t,                 \
			   head_notify_deleted_sessions, name)
#endif
