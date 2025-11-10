#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "lua_plugin.h"

#include <stdarg.h>
#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

VLIB_REGISTER_LOG_CLASS (lua_log) = {
  .class_name = "lua",
  .subclass_name = "glue",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)

struct vpp_lua_table_handle
{
  vpp_lua_table_handle_t parent;
  vpp_lua_table_handle_t *children;
  u8 *name;
  int ref;
  vpp_lua_ns_handle_t ns_handle;
};

struct vpp_lua_handle_t
{
  lua_State *L;
  vpp_lua_table_handle_t *table_handles;
  vpp_lua_ns_handle_t *namespaces;
};

struct vpp_lua_method_t
{
  vpp_lua_string_function_t func;
  void *cookie;
  vpp_lua_handle_t handle;
  const void *context;
  size_t context_size;
  u8 *context_buffer;
};

typedef struct
{
  const char *name;
  u8 needs_argument;
} vpp_lua_ns_rt_method_t;

typedef struct
{
  vpp_lua_ns_resolver_fn_t context_resolver;
  vpp_lua_type_t *args;
} vpp_lua_fn_and_args_t;

struct vpp_lua_ns_t
{
  u32 context_size;
  vpp_lua_ns_rt_method_t *methods;
  vpp_lua_table_handle_t table_handle;
  vpp_lua_fn_and_args_t *fn_and_args_vec;
};

static u8 *
format_vpp_lua_table_path (u8 *s, va_list *args)
{
  vpp_lua_table_handle_t handle = va_arg (*args, vpp_lua_table_handle_t);
  vpp_lua_table_handle_t *stack = 0;

  if (handle == 0)
    return format (s, "%s", "<table>");

  for (vpp_lua_table_handle_t current = handle; current;
       current = current->parent)
    vec_add1 (stack, current);

  for (int i = vec_len (stack) - 1; i >= 0; --i)
    {
      vpp_lua_table_handle_t node = stack[i];
      if (node == 0 || node->name == 0 || node->name[0] == 0)
	continue;

      if (vec_len (s))
	s = format (s, "%c", '.');

      s = format (s, "%s", node->name);
    }

  if (vec_len (s) == 0)
    s = format (s, "%s", "<table>");

  vec_free (stack);
  return s;
}

static vpp_lua_type_t
vpp_lua_type_from_lua (lua_State *L, int index)
{
  switch (lua_type (L, index))
    {
    case LUA_TSTRING:
      return VPP_LUA_T_STRING;
    case LUA_TNUMBER:
      return VPP_LUA_T_NUMBER;
    case LUA_TBOOLEAN:
      return VPP_LUA_T_BOOL;
    default:
      return (vpp_lua_type_t) ~0;
    }
}

static vpp_lua_method_handle_t
vpp_lua_cfunction_runtime (lua_State *L, int idx, vpp_lua_table_handle_t th,
			   const char *method_name)
{
  if (!lua_iscfunction (L, idx))
    {
      log_err ("namespace '%U' method '%s' is not a C function",
	       format_vpp_lua_table_path, th,
	       method_name ? method_name : "<unnamed>");
      return 0;
    }

  const char *upvalue_name = lua_getupvalue (L, idx, 1);
  if (upvalue_name == 0)
    {
      log_err ("namespace '%U' method '%s' has no runtime upvalue",
	       format_vpp_lua_table_path, th,
	       method_name ? method_name : "<unnamed>");
      return 0;
    }

  vpp_lua_method_handle_t mh = lua_touserdata (L, -1);
  lua_pop (L, 1);

  if (mh == 0)
    {
      log_err ("namespace '%U' method '%s' runtime pointer is NULL",
	       format_vpp_lua_table_path, th,
	       method_name ? method_name : "<unnamed>");
      return 0;
    }

  return mh;
}

vpp_lua_handle_t
vpp_lua_create (void)
{
  struct vpp_lua_handle_t *h =
    clib_mem_alloc (sizeof (struct vpp_lua_handle_t));

  *h = (struct vpp_lua_handle_t){
    .L = luaL_newstate (),
  };
  luaL_openlibs (h->L);

  return h;
}

void
vpp_lua_destroy (vpp_lua_handle_t h)
{
  if (h == 0)
    return;

  lua_State *L = h->L;

  if (h->table_handles)
    {
      vec_foreach_pointer (th, h->table_handles)
	{
	  if (th == 0)
	    continue;
	  vec_free (th->children);
	  vec_free (th->name);
	  if (L && th->ref != LUA_NOREF)
	    luaL_unref (L, LUA_REGISTRYINDEX, th->ref);
	  clib_mem_free (th);
	}
      vec_free (h->table_handles);
    }

  if (h->namespaces)
    {
      vec_foreach_pointer (nh, h->namespaces)
	{
	  if (!nh)
	    continue;
	  if (nh->fn_and_args_vec)
	    {
	      vpp_lua_fn_and_args_t *fa;
	      vec_foreach (fa, nh->fn_and_args_vec)
		vec_free (fa->args);
	      vec_free (nh->fn_and_args_vec);
	    }
	  vec_free (nh->methods);
	  clib_mem_free (nh);
	}
      vec_free (h->namespaces);
      h->namespaces = 0;
    }

  lua_close (h->L);
  clib_mem_free (h);
}

static lua_State *
vpp_lua_handle_state (vpp_lua_handle_t h)
{
  return h ? h->L : 0;
}

static vpp_lua_table_handle_t
vpp_lua_table_find_child (vpp_lua_handle_t h, vpp_lua_table_handle_t parent,
			  const char *name)
{
  if (h == 0 || name == 0)
    return 0;

  if (parent)
    {
      vpp_lua_table_handle_t *hp = 0;
      vec_foreach (hp, parent->children)
	{
	  vpp_lua_table_handle_t child = *hp;
	  if (child && child->name &&
	      strcmp ((const char *) child->name, name) == 0)
	    return child;
	}
      return 0;
    }

  vpp_lua_table_handle_t *hp = 0;
  vec_foreach (hp, h->table_handles)
    {
      vpp_lua_table_handle_t handle = *hp;
      if (handle && handle->parent == 0 && handle->name &&
	  strcmp ((const char *) handle->name, name) == 0)
	return handle;
    }

  return 0;
}

vpp_lua_table_handle_t
vpp_lua_table_add (vpp_lua_handle_t h, const char *name,
		   vpp_lua_table_handle_t parent)
{
  lua_State *L = vpp_lua_handle_state (h);
  ASSERT (name && name[0] != '\0');

  if (h == 0 || L == 0)
    return 0;

  vpp_lua_table_handle_t existing = vpp_lua_table_find_child (h, parent, name);
  if (existing)
    return existing;

  int table_index = 0;

  if (parent == 0)
    {
      lua_getglobal (L, name);
      if (lua_isnil (L, -1))
	{
	  lua_pop (L, 1);
	  lua_newtable (L);
	  lua_pushvalue (L, -1);
	  lua_setglobal (L, name);
	}
      else if (!lua_istable (L, -1))
	{
	  lua_pop (L, 1);
	  log_err ("global '%s' exists but is not a table", name);
	  return 0;
	}
      table_index = lua_gettop (L);
    }
  else
    {
      lua_rawgeti (L, LUA_REGISTRYINDEX, parent->ref);
      if (!lua_istable (L, -1))
	{
	  lua_pop (L, 1);
	  log_err ("parent table handle for '%s' is invalid", name);
	  return 0;
	}

      lua_getfield (L, -1, name);
      if (lua_isnil (L, -1))
	{
	  lua_pop (L, 1);
	  lua_newtable (L);
	  lua_pushvalue (L, -1);
	  lua_setfield (L, -3, name);
	}
      else if (!lua_istable (L, -1))
	{
	  u8 *parent_path =
	    format (0, "%U", format_vpp_lua_table_path, parent);
	  lua_pop (L, 2);
	  log_err ("'%v.%s' exists but is not a table", parent_path, name);
	  vec_free (parent_path);
	  return 0;
	}

      lua_remove (L, -2); /* drop parent table, keep child */
      table_index = lua_gettop (L);
    }

  lua_pushvalue (L, table_index);
  int ref = luaL_ref (L, LUA_REGISTRYINDEX);
  lua_pop (L, 1); /* drop original table */

  vpp_lua_table_handle_t handle = clib_mem_alloc (sizeof (*handle));
  clib_memset (handle, 0, sizeof (*handle));
  handle->parent = parent;
  handle->name = (u8 *) format (0, "%s", name);
  handle->ref = ref;
  handle->ns_handle = 0;
  handle->children = 0;

  if (parent)
    vec_add1 (parent->children, handle);

  vec_add1 (h->table_handles, handle);
  return handle;
}

static int
vpp_lua_string_function_thunk (lua_State *L)
{
  /* lua_touserdata retrieves the runtime pointer captured as upvalue #1. */
  vpp_lua_method_handle_t mh = lua_touserdata (L, lua_upvalueindex (1));
  size_t argument_length = 0;
  const char *argument = 0;
  vpp_lua_string_function_args_t args;
  const char *value = 0;

  if (mh == 0 || mh->func == 0)
    {
      /* lua_pushnil pushes a nil result for missing functions. */
      lua_pushnil (L);
      /* lua_pushboolean pushes the error flag (true => failure). */
      lua_pushboolean (L, 1);
      return 2;
    }

  if (!lua_isnoneornil (L, 1))
    /* luaL_checklstring validates and reads the first argument as a string. */
    argument = luaL_checklstring (L, 1, &argument_length);

  args.handle = mh->handle;
  args.cookie = mh->cookie;
  args.argument = argument;
  args.argument_length = argument ? argument_length : 0;
  args.context = mh->context;
  args.context_size = mh->context_size;
  args.error_message = 0;

  if (mh->context_size > 0 && args.context == 0)
    log_err ("string thunk missing context: func=%p size=%u", mh,
	     (u32) mh->context_size);

  log_debug ("string thunk func=%p ctx=%p size=%u", (void *) mh->func,
	     args.context, (u32) args.context_size);

  value = mh->func (&args);

  if (mh->context_buffer)
    {
      vec_reset_length (mh->context_buffer);
      mh->context = mh->context_buffer;
      mh->context_size = vec_len (mh->context_buffer);
    }
  else
    {
      mh->context = 0;
      mh->context_size = 0;
    }

  if (value)
    /* lua_pushstring pushes the function result string. */
    lua_pushstring (L, value);
  else
    /* lua_pushnil signals a nil result when value is absent. */
    lua_pushnil (L);

  if (args.error_message)
    /* lua_pushstring pushes the error description. */
    lua_pushstring (L, args.error_message);
  else
    lua_pushnil (L);

  return 2;
}

vpp_lua_method_handle_t
vpp_lua_method_add (vpp_lua_handle_t h, const vpp_lua_string_func_desc_t *desc)
{
  lua_State *L = vpp_lua_handle_state (h);
  vpp_lua_table_handle_t th = desc->table_handle;
  const char *method = desc->method;
  vpp_lua_method_handle_t mh = 0;

  ASSERT (th);
  ASSERT (method && method[0] != '\0');
  ASSERT (desc->func);

  lua_rawgeti (L, LUA_REGISTRYINDEX, th->ref);
  ASSERT (lua_istable (L, -1));

  /* lua_newuserdatauv allocates a userdata block for runtime state. */
  mh = lua_newuserdatauv (L, sizeof (*mh), 0);
  clib_memset (mh, 0, sizeof (*mh));

  mh->func = desc->func;
  mh->cookie = desc->cookie;
  mh->handle = h;

  /* lua_pushcclosure creates the callable C closure with one upvalue. */
  lua_pushcclosure (L, vpp_lua_string_function_thunk, 1);
  /* lua_setfield assigns the closure into the namespace table. */
  lua_setfield (L, -2, method);

  if (th->ns_handle)
    {
      vpp_lua_ns_handle_t nh = th->ns_handle;
      vpp_lua_ns_rt_method_t slot;
      const char *ns_method = method;

      lua_getfield (L, -1, ns_method);
      ASSERT (lua_isfunction (L, -1));

      if (!vpp_lua_cfunction_runtime (L, -1, th, ns_method ? ns_method : ""))
	{
	  lua_pop (L, 2); /* drop function and table */
	  log_err ("%U.%s is not callable", format_vpp_lua_table_path, th,
		   ns_method);
	  return 0;
	}
      lua_pop (L, 1); /* drop function; leave table on stack */

      slot = (vpp_lua_ns_rt_method_t){
	.name = ns_method,
	.needs_argument = desc->ns_needs_argument ? 1 : 0,
      };

      vec_add1 (nh->methods, slot);

      log_debug ("attached method %U.%s", format_vpp_lua_table_path, th,
		 ns_method);
    }

  /* lua_pop removes the namespace table from the stack. */
  lua_pop (L, 1);

  log_debug ("registered %U.%s()", format_vpp_lua_table_path, th, method);

  return mh;
}

clib_error_t *
vpp_lua_run_string (vpp_lua_handle_t h, const char *code)
{
  lua_State *L = vpp_lua_handle_state (h);

  ASSERT (L != 0);
  ASSERT (code != 0);

  /* luaL_loadstring compiles the provided chunk onto the stack. */
  if (luaL_loadstring (L, code) != LUA_OK)
    {
      const char *msg = lua_tostring (L, -1);
      clib_error_t *err =
	clib_error_return (0, "lua load failure: %s", msg ? msg : "<nil>");
      lua_pop (L, 1); /* drop error message */
      return err;
    }

  /* lua_pcall executes the chunk with protected error handling. */
  if (lua_pcall (L, 0, 0, 0) != LUA_OK)
    {
      const char *msg = lua_tostring (L, -1);
      clib_error_t *err =
	clib_error_return (0, "lua runtime failure: %s", msg ? msg : "<nil>");
      lua_pop (L, 1); /* drop runtime error */
      return err;
    }

  return 0;
}

static int
vpp_lua_namespace_method_call (lua_State *L)
{
  /* lua_touserdata reads the captured method descriptor. */
  vpp_lua_ns_rt_method_t *method = lua_touserdata (L, lua_upvalueindex (1));
  /* lua_touserdata retrieves the namespace runtime context. */
  vpp_lua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (4));
  u32 ctx_sz = nh->context_size;
  /* lua_touserdata grabs the string-function runtime for callbacks. */
  vpp_lua_method_handle_t mh = lua_touserdata (L, lua_upvalueindex (5));
  /* lua_touserdata pulls the captured context userdata if any. */
  void *context_mem =
    ctx_sz > 0 ? lua_touserdata (L, lua_upvalueindex (2)) : 0;
  /* lua_gettop reports how many arguments the user supplied. */
  int argc = lua_gettop (L);

  log_debug ("ns_call method=%s runtime=%p func=%p ctx=%p size=%u need_arg=%u",
	     method && method->name ? method->name : "<unnamed>", nh, mh,
	     context_mem, ctx_sz, method->needs_argument);

  if (method->needs_argument)
    {
      luaL_argcheck (L, argc >= 1, 1, "argument required");
      luaL_argcheck (L, argc == 1, 1, "single argument expected");
    }
  else
    luaL_argcheck (L, argc == 0, 1, "no arguments expected");

  /* lua_pushvalue duplicates the raw string function for pcalls. */
  lua_pushvalue (L, lua_upvalueindex (3));
  /* lua_insert moves the function below user arguments. */
  lua_insert (L, 1);

  if (mh && context_mem && ctx_sz > 0)
    {
      log_debug ("ns_call method=%s copying context %p (%u bytes) into %p",
		 method && method->name ? method->name : "<unnamed>",
		 context_mem, ctx_sz, mh);
      vec_validate (mh->context_buffer, ctx_sz - 1);
      clib_memcpy_fast (mh->context_buffer, context_mem, ctx_sz);
      mh->context = mh->context_buffer;
      mh->context_size = ctx_sz;
    }
  else if (ctx_sz > 0)
    log_err ("ns_call missing context: method=%s mh=%p context_mem=%p "
	     "size=%u",
	     method && method->name ? method->name : "<unnamed>", (void *) mh,
	     context_mem, ctx_sz);

  if (lua_pcall (L, argc, 2, 0) != LUA_OK)
    {
      if (mh)
	{
	  mh->context = 0;
	  mh->context_size = 0;
	}
      /* lua_error rethrows the failure to the caller. */
      return lua_error (L);
    }

  if (mh)
    {
      mh->context = 0;
      mh->context_size = 0;
    }

  return 2;
}

static int
vpp_lua_namespace_call (lua_State *L)
{
  /* lua_touserdata fetches the namespace runtime stored as upvalue #2. */
  vpp_lua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (2));
  vpp_lua_ns_rt_method_t *method = 0;
  vpp_lua_method_handle_t mh = 0;
  vpp_lua_table_handle_t th = nh->table_handle;
  vpp_lua_ns_resolver_fn_t cr = 0;
  void *context_mem = 0;
  const char *resolve_error = 0;
  int namespace_index = 0;
  int context_index = 0;
  int handle_index = 0;
  uword method_count = 0;
  u32 ctx_sz = nh->context_size;
  int total_args = lua_gettop (L);
  int user_argc = total_args - 1;
  bool args_match = false;

  method_count = vec_len (nh->methods);
  if (method_count == 0)
    {
      log_err ("namespace '%U' has no methods", format_vpp_lua_table_path, th);
      u8 *s = format (0, "%U%c", format_vpp_lua_table_path, th, 0);
      lua_pushfstring (L, "namespace '%s' has no methods", (char *) s);
      vec_free (s);
      return lua_error (L);
    }

  /* luaL_checktype ensures the first argument is a table (namespace proxy). */
  luaL_checktype (L, 1, LUA_TTABLE);

  if (vec_len (nh->fn_and_args_vec) > 0)
    {
      vpp_lua_fn_and_args_t *fa;
      vec_foreach (fa, nh->fn_and_args_vec)
	{
	  if (vec_len (fa->args) != user_argc)
	    continue;

	  args_match = true;
	  for (int i = 0; i < user_argc; ++i)
	    {
	      if (fa->args[i] != vpp_lua_type_from_lua (L, 2 + i))
		{
		  args_match = false;
		  break;
		}
	    }

	  if (args_match)
	    {
	      cr = fa->context_resolver;
	      break;
	    }
	}

      if (!args_match)
	{
	  log_err ("namespace '%U' called with unsupported arguments",
		   format_vpp_lua_table_path, th);
	  u8 *s = format (0, "%U%c", format_vpp_lua_table_path, th, 0);
	  lua_pushfstring (
	    L, "namespace '%s' called with unsupported arguments", (char *) s);
	  vec_free (s);
	  return lua_error (L);
	}
    }
  else
    {
      luaL_argcheck (L, user_argc == 1, 2, "single argument expected");
      luaL_checktype (L, 2, LUA_TSTRING);
    }

  size_t name_len = 0;
  const char *name = (ctx_sz > 0) ? luaL_checklstring (L, 2, &name_len) : 0;

  /* lua_pushvalue duplicates the namespace table upvalue. */
  lua_pushvalue (L, lua_upvalueindex (1));
  namespace_index = lua_gettop (L);

  if (ctx_sz > 0)
    {
      /* lua_newuserdatauv allocates per-handle context storage. */
      context_mem = lua_newuserdatauv (L, ctx_sz, 0);
      clib_memset (context_mem, 0, ctx_sz);
      if (cr)
	{
	  vpp_lua_ns_resolver_fn_args_t resolver_args = {
	    .context = context_mem,
	    .name = name,
	    .name_len = name_len,
	    .error_message = &resolve_error,
	  };
	  if (!cr (&resolver_args))
	    {
	      log_warn ("context resolution failed for %U('%.*s')",
			format_vpp_lua_table_path, nh->table_handle,
			(int) name_len, name);
	      lua_pop (L, 1); /* discard temporary namespace table */
	      /* luaL_error raises a Lua error with the resolver message. */
	      return luaL_error (L, "%s",
				 resolve_error ?
				   resolve_error :
				   "namespace context resolution failed");
	    }
	}
    }
  else
    lua_pushnil (L); /* placeholder context object */
  context_index = lua_gettop (L);

  /* lua_createtable prepares the method handle table. */
  lua_createtable (L, 0, method_count);
  handle_index = lua_gettop (L);

  vec_foreach (method, nh->methods)
    {
      if (method->name == 0)
	continue;

      lua_pushvalue (L, namespace_index);
      /* lua_getfield loads the raw string function from the namespace. */
      lua_getfield (L, -1, method->name);
      if (!lua_isfunction (L, -1))
	{
	  log_warn ("namespace '%U' method '%s' is not callable",
		    format_vpp_lua_table_path, nh->table_handle,
		    method->name ? method->name : "<unnamed>");
	  lua_pop (L, 2); /* drop namespace and result */
	  continue;
	}

      mh = vpp_lua_cfunction_runtime (
	L, -1, nh->table_handle, method->name ? method->name : "<unnamed>");
      if (mh == 0)
	{
	  lua_pop (L, 2);
	  continue;
	}

      lua_pushlightuserdata (L, method); /* capture method descriptor */
      lua_pushvalue (L, context_index);	 /* capture resolved context */
      lua_pushvalue (L, -3);		 /* capture original string function */
      lua_pushlightuserdata (L, nh);	 /* capture namespace runtime */
      lua_pushlightuserdata (L, mh);	 /* capture method runtime */
      /* lua_pushcclosure builds the bound method closure with five upvalues.
       */
      lua_pushcclosure (L, vpp_lua_namespace_method_call, 5);
      /* lua_setfield stores the closure into the handle table. */
      lua_setfield (L, handle_index, method->name);

      lua_pop (L, 2); /* drop namespace and raw function */
    }

  lua_remove (L, context_index);   /* discard temporary context storage */
  lua_remove (L, namespace_index); /* discard namespace table */

  return 1;
}

vpp_lua_ns_handle_t
vpp_lua_ns_create (vpp_lua_handle_t h, const vpp_lua_ns_create_args_t *a)
{
  lua_State *L = vpp_lua_handle_state (h);
  vpp_lua_table_handle_t th = a->table_handle;
  vpp_lua_ns_handle_t nh = 0;
  int ns_index;
  int mt_index;

  ASSERT (a != 0);
  ASSERT (th);
  ASSERT (!th->ns_handle);

  nh = clib_mem_alloc (sizeof (*nh));
  vec_add1 (h->namespaces, nh);

  *nh = (struct vpp_lua_ns_t){
    .table_handle = th,
    .context_size = a->context_size,
  };

  th->ns_handle = nh;

  lua_rawgeti (L, LUA_REGISTRYINDEX, th->ref);
  ASSERT (lua_istable (L, -1));

  ns_index = lua_gettop (L);

  if (!lua_getmetatable (L, ns_index))
    {
      lua_newtable (L);		      /* metatable container */
      lua_pushvalue (L, -1);	      /* duplicate metatable */
      lua_setmetatable (L, ns_index); /* assign metatable to namespace */
    }
  mt_index = lua_gettop (L);

  lua_pushvalue (L, ns_index);	 /* duplicate namespace table */
  lua_pushlightuserdata (L, nh); /* capture runtime pointer */
  lua_pushcclosure (L, vpp_lua_namespace_call, 2); /* build __call closure */
  lua_setfield (L, mt_index, "__call");		   /* store metamethod */
  lua_pop (L, 2); /* drop namespace + metatable */

  log_debug ("enabled namespace %U", format_vpp_lua_table_path, th);
  return nh;
}

void
vpp_lua_ns_add_call_args (vpp_lua_ns_handle_t nh, vpp_lua_ns_resolver_fn_t fn,
			  u32 n_args, ...)
{
  vpp_lua_fn_and_args_t *fa;
  va_list va;

  vec_add2 (nh->fn_and_args_vec, fa, 1);
  fa->context_resolver = fn;
  va_start (va, n_args);

  for (u32 i = 0; i < n_args; i++)
    {
      vpp_lua_type_t t = (vpp_lua_type_t) va_arg (va, int);
      vec_add1 (fa->args, t);
    }

  va_end (va);
}
