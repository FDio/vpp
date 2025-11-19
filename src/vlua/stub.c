#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <vlua/vlua.h>
#include <vlua/internal.h>

#include <stdio.h>
#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

static const char *
vlua_stub_type_name (vlua_type_t t)
{
  switch (t)
    {
    case VLUA_T_STRING:
      return "string";
    case VLUA_T_NUMBER:
      return "number";
    case VLUA_T_INTEGER:
      return "integer";
    case VLUA_T_BOOL:
      return "bool";
    case VLUA_T_NIL:
      return "nil";
    case VLUA_T_TABLE:
      return "table";
    default:
      return "unknown";
    }
}

static bool
vlua_stub_has_path (u8 **paths, const char *path)
{
  u8 **entry_ptr;
  vec_foreach (entry_ptr, paths)
    if (strcmp ((const char *) *entry_ptr, path) == 0)
      return true;
  return false;
}

static void
vlua_stub_add_path (u8 ***paths, const char *path)
{
  if (!path || !path[0])
    return;
  if (vlua_stub_has_path (*paths, path))
    return;
  vec_add1 (*paths, (u8 *) format (0, "%s", path));
}

static void
vlua_stub_collect_table_paths (vlua_handle_t h, u8 ***paths)
{
  vlua_table_handle_t *handles = h->table_handles;
  for (uword i = 0; i < vec_len (handles); ++i)
    {
      vlua_table_handle_t th = handles[i];
      u8 *path = format (0, "%U", vlua_format_table_path, th);
      char *full;
      if (!vec_len (path) || path[0] == '<')
	{
	  vec_free (path);
	  continue;
	}
      path = format (path, "%c", 0);
      full = (char *) path;
      vlua_stub_add_path (paths, full);
      for (char *dot = strchr (full, '.'); dot; dot = strchr (dot + 1, '.'))
	{
	  u8 *prefix = format (0, "%.*s%c", (int) (dot - full), full, 0);
	  vlua_stub_add_path (paths, (const char *) prefix);
	  vec_free (prefix);
	}
      vec_free (path);
    }
}
static void
vlua_stub_emit_signature (FILE *fp, const vlua_fn_and_args_t *sig,
			  const char *ret_type)
{
  const vlua_type_t *type_ptr;
  bool first = true;

  fprintf (fp, "---@overload fun(");
  vec_foreach (type_ptr, sig->args)
    {
      const char *type_name = vlua_stub_type_name (*type_ptr);
      fprintf (fp, "%sarg%d:%s", first ? "" : ", ",
	       (int) (type_ptr - sig->args + 1), type_name);
      first = false;
    }
  fprintf (fp, ")");
  if (ret_type)
    fprintf (fp, ":%s", ret_type);
  fprintf (fp, "\n");
}

static int
vlua_stub_path_cmp (const void *a, const void *b)
{
  const char *sa = (const char *) (const u8 *const *) a;
  const char *sb = (const char *) (const u8 *const *) b;
  int depth_a = 0, depth_b = 0;
  for (const char *p = sa; *p; ++p)
    if (*p == '.')
      depth_a++;
  for (const char *p = sb; *p; ++p)
    if (*p == '.')
      depth_b++;
  if (depth_a != depth_b)
    return depth_a - depth_b;
  return strcmp (sa, sb);
}

__clib_export void
vlua_stub_dump (vlua_handle_t h, const char *path)
{
  u8 **table_paths = 0;
  FILE *fp;
  u8 **path_it;
  vlua_ns_handle_t *nh_ptr;
  vlua_method_handle_t *mh_ptr;
  u8 **entry_ptr;

  if (!path || !path[0])
    return;

  vlua_stub_collect_table_paths (h, &table_paths);
  vec_sort_with_function (table_paths, vlua_stub_path_cmp);

  fp = fopen (path, "w");
  if (!fp)
    {
      clib_warning ("failed to open EmmyLua stub file %s", path);
      vec_foreach (entry_ptr, table_paths)
	vec_free (*entry_ptr);
      vec_free (table_paths);
      return;
    }

  fprintf (fp, "--- Auto-generated EmmyLua stubs\n\n");

  vec_foreach (path_it, table_paths)
    {
      u8 *entry = *path_it;
      fprintf (fp, "%s = %s or {}\n\n", (char *) entry, (char *) entry);
    }

  vec_foreach (nh_ptr, h->namespaces)
    {
      vlua_ns_handle_t nh = *nh_ptr;
      u8 *ns_path;
      vlua_fn_and_args_t *sig;

      if (!nh)
	continue;

      ns_path = format (0, "%U", vlua_format_table_path, nh->table_handle);
      ns_path = format (ns_path, "%c", 0);

      fprintf (fp, "--- namespace %s\n", (char *) ns_path);
      vec_foreach (sig, nh->signatures)
	vlua_stub_emit_signature (fp, sig, "table");
      fprintf (fp, "function %s(...) end\n\n", (char *) ns_path);

      vec_free (ns_path);
    }

  vec_foreach (mh_ptr, h->methods)
    {
      vlua_method_handle_t mh = *mh_ptr;
      u8 *tbl_path;
      u8 *full_path;
      vlua_fn_and_args_t *sig;

      if (!mh || !mh->name)
	continue;

      tbl_path = format (0, "%U", vlua_format_table_path, mh->table_handle);
      if (vec_len (tbl_path))
	full_path = format (0, "%v.%s%c", tbl_path, mh->name, 0);
      else
	full_path = format (0, "%s%c", mh->name, 0);
      vec_free (tbl_path);

      fprintf (fp, "--- method %s\n", (char *) full_path);
      vec_foreach (sig, mh->signatures)
	vlua_stub_emit_signature (fp, sig, 0);
      fprintf (fp, "function %s(...) end\n\n", (char *) full_path);

      vec_free (full_path);
    }

  fclose (fp);
  vec_foreach (path_it, table_paths)
    vec_free (*path_it);
  vec_free (table_paths);
}
