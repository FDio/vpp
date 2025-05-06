/*
 * gpcapng_filter_api.c - Implementation of pluggable filter API
 *
 * Copyright (c) 2024 Cisco Systems, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>

#include "gpcapng.h"
#include "gpcapng_filter_api.h"
#include "public_inlines.h"
#include "exports.h"
#include "destination.h"

/* Storage for registered filter implementations */
typedef struct
{
  /* Vector of registered implementations */
  gpcapng_filter_impl_t *implementations;

  /* Hash table: name -> index in implementations vector */
  uword *impl_by_name;

  /* Currently active implementation index */
  u32 active_impl_index;

  /* Lock for implementation switching */
  clib_spinlock_t lock;
} gpcapng_filter_registry_t;

static gpcapng_filter_registry_t filter_registry;

/* Register a filter implementation */
int
gpcapng_register_filter_impl (gpcapng_filter_impl_t *impl)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  uword *p;
  u32 index;

  if (!impl || !impl->name || !impl->selected_fn)
    return -1;

  /* Check API version compatibility */
  if (impl->api_version != GPCAPNG_FILTER_API_VERSION)
    {
      clib_warning ("Filter implementation '%s' uses incompatible API version "
		    "%u (expected %u)",
		    impl->name, impl->api_version, GPCAPNG_FILTER_API_VERSION);
      return -2;
    }

  clib_spinlock_lock (&reg->lock);

  /* Check if already registered */
  p = hash_get_mem (reg->impl_by_name, impl->name);
  if (p)
    {
      clib_spinlock_unlock (&reg->lock);
      return -3; /* Already registered */
    }

  /* Add to implementations vector */
  index = vec_len (reg->implementations);
  vec_add1 (reg->implementations, *impl);

  /* Duplicate the name for hash table */
  reg->implementations[index].name =
    (char *) format (0, "%s%c", impl->name, 0);

  /* Add to hash table */
  hash_set_mem (reg->impl_by_name, reg->implementations[index].name, index);

  /* If this is the first implementation or has higher priority, make it active
   */
  if (index == 0 ||
      (reg->active_impl_index < vec_len (reg->implementations) &&
       impl->priority > reg->implementations[reg->active_impl_index].priority))
    {
      reg->active_impl_index = index;
    }

  clib_spinlock_unlock (&reg->lock);

  return 0;
}

/* Unregister a filter implementation */
int
gpcapng_unregister_filter_impl (const char *name)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  uword *p;
  u32 index;

  if (!name)
    return -1;

  clib_spinlock_lock (&reg->lock);

  p = hash_get_mem (reg->impl_by_name, name);
  if (!p)
    {
      clib_spinlock_unlock (&reg->lock);
      return -2; /* Not found */
    }

  index = p[0];

  /* Can't unregister the active implementation */
  if (index == reg->active_impl_index)
    {
      clib_spinlock_unlock (&reg->lock);
      return -3; /* Currently active */
    }

  /* Remove from hash table */
  hash_unset_mem (reg->impl_by_name, name);

  /* Free the name */
  vec_free (reg->implementations[index].name);

  /* Mark as invalid (don't remove from vector to preserve indices) */
  reg->implementations[index].selected_fn = NULL;

  clib_spinlock_unlock (&reg->lock);

  return 0;
}

/* Get current active filter implementation */
gpcapng_filter_impl_t *
gpcapng_get_active_filter_impl (void)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  gpcapng_filter_impl_t *impl = NULL;

  clib_spinlock_lock (&reg->lock);

  if (reg->active_impl_index < vec_len (reg->implementations))
    {
      impl = &reg->implementations[reg->active_impl_index];
      if (!impl->selected_fn)
	impl = NULL; /* Implementation was unregistered */
    }

  clib_spinlock_unlock (&reg->lock);

  return impl;
}

/* Set active filter implementation by name */
int
gpcapng_set_active_filter_impl (const char *name)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  uword *p;
  u32 new_index;

  if (!name)
    return -1;

  clib_spinlock_lock (&reg->lock);

  p = hash_get_mem (reg->impl_by_name, name);
  if (!p)
    {
      clib_spinlock_unlock (&reg->lock);
      return -2; /* Not found */
    }

  new_index = p[0];

  /* Verify implementation is still valid */
  if (!reg->implementations[new_index].selected_fn)
    {
      clib_spinlock_unlock (&reg->lock);
      return -3; /* Implementation was unregistered */
    }

  /* Use memory barrier to ensure all workers see the change */
  CLIB_MEMORY_BARRIER ();
  reg->active_impl_index = new_index;
  CLIB_MEMORY_BARRIER ();

  clib_spinlock_unlock (&reg->lock);

  return 0;
}

/* Get filter implementation by name */
gpcapng_filter_impl_t *
gpcapng_get_filter_impl_by_name (const char *name)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  gpcapng_filter_impl_t *impl = NULL;
  uword *p;
  u32 index;

  if (!name)
    return NULL;

  clib_spinlock_lock (&reg->lock);

  p = hash_get_mem (reg->impl_by_name, name);
  if (p)
    {
      index = p[0];
      if (reg->implementations[index].selected_fn)
	impl = &reg->implementations[index];
    }

  clib_spinlock_unlock (&reg->lock);

  return impl;
}

/* List all registered filter implementations */
void
gpcapng_list_filter_impls (vlib_main_t *vm)
{
  gpcapng_filter_registry_t *reg = &filter_registry;
  gpcapng_filter_impl_t *impl;
  u32 i;

  clib_spinlock_lock (&reg->lock);

  vlib_cli_output (vm, "Registered GPCAPNG filter implementations:");
  vlib_cli_output (vm, "%-20s %-10s %-50s %s", "Name", "Priority",
		   "Description", "Status");
  vlib_cli_output (
    vm, "%-20s %-10s %-50s %s", "--------------------", "----------",
    "--------------------------------------------------", "------");

  vec_foreach_index (i, reg->implementations)
    {
      impl = &reg->implementations[i];
      if (!impl->selected_fn)
	continue; /* Skip unregistered entries */

      vlib_cli_output (vm, "%-20s %-10u %-50s %s", impl->name, impl->priority,
		       impl->description ? impl->description :
					   "(no description)",
		       i == reg->active_impl_index ? "ACTIVE" : "");
    }

  if (vec_len (reg->implementations) == 0)
    {
      vlib_cli_output (vm, "No filter implementations registered");
    }

  clib_spinlock_unlock (&reg->lock);
}

/* CLI command to show filter implementations */
static clib_error_t *
gpcapng_show_filter_impls_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  gpcapng_list_filter_impls (vm);
  return 0;
}

VLIB_CLI_COMMAND (gpcapng_show_filter_impls_command, static) = {
  .path = "show gpcapng filter-implementations",
  .short_help = "show gpcapng filter-implementations",
  .function = gpcapng_show_filter_impls_command_fn,
};

/* CLI command to set active filter implementation */
static clib_error_t *
gpcapng_set_filter_impl_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *impl_name = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected filter implementation name");

  if (unformat (line_input, "%s", &impl_name))
    {
      rv = gpcapng_set_active_filter_impl ((char *) impl_name);

      switch (rv)
	{
	case 0:
	  vlib_cli_output (vm, "Active filter implementation set to: %s",
			   impl_name);
	  break;
	case -2:
	  vlib_cli_output (vm, "Error: Filter implementation '%s' not found",
			   impl_name);
	  break;
	default:
	  vlib_cli_output (
	    vm, "Error: Failed to set filter implementation (error %d)", rv);
	  break;
	}

      vec_free (impl_name);
    }
  else
    {
      vlib_cli_output (vm, "Error: Filter implementation name required");
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (gpcapng_set_filter_impl_command, static) = {
  .path = "gpcapng set-filter-implementation",
  .short_help = "gpcapng set-filter-implementation <name>",
  .function = gpcapng_set_filter_impl_command_fn,
};

/* Initialize filter registry */
static clib_error_t *
gpcapng_filter_api_init (vlib_main_t *vm)
{
  gpcapng_filter_registry_t *reg = &filter_registry;

  clib_spinlock_init (&reg->lock);
  reg->impl_by_name = hash_create_string (0, sizeof (uword));
  reg->active_impl_index = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (gpcapng_filter_api_init);

/* Export vtable for other plugins */
__clib_export clib_error_t *
gpcapng_plugin_methods_vtable_init (gpcapng_plugin_methods_t *m)
{
  m->register_filter_impl = gpcapng_register_filter_impl;
  m->unregister_filter_impl = gpcapng_unregister_filter_impl;
  m->get_active_filter_impl = gpcapng_get_active_filter_impl;
  m->set_active_filter_impl = gpcapng_set_active_filter_impl;
  m->get_filter_impl_by_name = gpcapng_get_filter_impl_by_name;
  m->list_filter_impls = gpcapng_list_filter_impls;
  m->find_destination_by_name = find_destination_by_name;
  m->get_capture_enabled_bitmap = gpcapng_get_capture_enabled_bitmap;
  return 0;
}