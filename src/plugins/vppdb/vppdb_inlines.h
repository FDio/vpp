#ifndef included_vppdb_inlines_h
#define included_vppdb_inlines_h

/*
 * Split a path string into a vector of path elements
 */
static char **
split_path(const char *pathname)
{
  assert(pathname);
  char **result = 0;
  const char *p = pathname;
  size_t s;
  const char *end = rindex(pathname, '\0');
  while (p < end) {
    s = strcspn(p, "/");
    if (s > 0) {
      char *slice = 0;
      vec_add(slice, p, s);
      vec_add1(result, slice);
    }
    p  = p + s + 1;
  }
  return result;
}

static void split_path_free(char **paths)
{
  assert(*paths);
  char **p;
  vec_foreach(p, paths) {
    vec_free(*p);
  }
  vec_free(paths);
}

#endif
