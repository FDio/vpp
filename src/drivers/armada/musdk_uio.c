/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>

#include <musdk_internal.h>

#define UIO_BASE_PATH	      "/sys/class/uio"
#define UIO_MAX_NUM	      255
#define UIO_INVALID_SIZE      0
#define UIO_INVALID_ADDR      (~0UL)
#define UIO_INVALID_FD	      -1
#define UIO_MMAP_NOT_DONE     0
#define UIO_MMAP_OK	      1
#define UIO_MMAP_FAILED	      2
#define UIO_HDR_STR	      "uio_%s"
#define UIO_ID_FORMAT_STR     "_%d"
#define UIO_MAX_FORMAT_SZ     (sizeof (UIO_HDR_STR) + sizeof (UIO_ID_FORMAT_STR))
#define MAX_FILE_NAME_LEN     64
#define INT_32_MAX_DEC_STR_SZ 10
#define UIO_PP2_STRING	      "pp"
#define UIO_PORT_STRING	      "uio_pp_port_%d:%d"
#define unlikely(x)	      __builtin_expect (!!(x), 0)
#define pr_err(...)	      fprintf (stderr, __VA_ARGS__)
#define pr_debug(...)

static void *
mem_calloc (size_t count, size_t size)
{
  size_t bytes;
  void *p;

  if (__builtin_mul_overflow (count, size, &bytes))
    return 0;
  p = clib_mem_alloc_or_null (bytes);
  if (p)
    memset (p, 0, bytes);
  return p;
}

static void uio_free_mem_info (struct uio_mem_t *);
static struct uio_mem_t *uio_find_mem_byname (struct uio_info_t *, const char *);
static void *uio_single_mmap (struct uio_info_t *, int, int);
static void uio_single_munmap (struct uio_info_t *, int);
static void iomem_uio_add_entry (struct uio_mem_t **, struct uio_mem_t *);
static struct uio_mem_t *iomem_uio_rm_entry (struct uio_mem_t **, const char *);
static void uio_free_info (struct uio_info_t *);
static void uio_free_dev_attrs (struct uio_info_t *);

static int
get_uio_num_from_filename (char *name)
{
  enum scan_states
  {
    ss_u,
    ss_i,
    ss_o,
    ss_num,
    ss_err
  };
  enum scan_states state = ss_u;
  int i = 0, num = -1;
  char ch = name[0];

  while (ch && (state != ss_err))
    {
      switch (ch)
	{
	case 'u':
	  if (state == ss_u)
	    state = ss_i;
	  else
	    state = ss_err;
	  break;
	case 'i':
	  if (state == ss_i)
	    state = ss_o;
	  else
	    state = ss_err;
	  break;
	case 'o':
	  if (state == ss_o)
	    state = ss_num;
	  else
	    state = ss_err;
	  break;
	default:
	  if ((ch >= '0') && (ch <= '9') && (state == ss_num))
	    {
	      if (num < 0)
		num = (ch - '0');
	      else
		num = (num * 10) + (ch - '0');
	    }
	  else
	    state = ss_err;
	}
      i++;
      ch = name[i];
    }
  if (state == ss_err)
    num = -1;

  return num;
}

static int
get_uio_line_from_file (char *filename, char *linebuf)
{
  char *s;
  int i;
  FILE *file = fopen (filename, "r");

  if (!file)
    return -1;

  memset (linebuf, 0, UIO_MAX_NAME_SIZE);
  s = fgets (linebuf, UIO_MAX_NAME_SIZE, file);
  if (!s)
    {
      fclose (file);
      return -2;
    }
  for (i = 0; (*s) && (i < UIO_MAX_NAME_SIZE); i++)
    {
      if (*s == '\n')
	*s = 0;
      s++;
    }
  fclose (file);

  return 0;
}

static struct uio_info_t *
get_uio_info_byname (char *name, const char *filter_name)
{
  struct uio_info_t *info;
  char linebuf[UIO_MAX_NAME_SIZE];
  char filename[255];

  snprintf (filename, sizeof (filename), "%s/%s/name", UIO_BASE_PATH, name);
  if (get_uio_line_from_file (filename, linebuf))
    return NULL;

  if (strncmp (linebuf, filter_name, strlen (filter_name)))
    return NULL;

  info = clib_mem_alloc_or_null (sizeof (struct uio_info_t));
  if (!info)
    return NULL;
  memset (info, 0, sizeof (struct uio_info_t));
  info->uio_num = get_uio_num_from_filename (name);

  return info;
}
static struct uio_info_t *
uio_find_devices_byname (const char *filter_name)
{
  struct dirent **namelist;
  struct uio_info_t *infolist = NULL, *infp, *last;
  int n;

  n = scandir (UIO_BASE_PATH, &namelist, 0, alphasort);
  if (n <= 0)
    {
      pr_err ("scandir for %s failed. errno = %d (%s)\n", UIO_BASE_PATH, errno, strerror (errno));
      return NULL;
    }
  while (n--)
    {
      infp = get_uio_info_byname (namelist[n]->d_name, filter_name);
      free (namelist[n]);
      if (!infp)
	continue;

      if (!infolist)
	infolist = infp;
      else
	last->next = infp;
      last = infp;
    }
  free (namelist);

  return infolist;
}

static int
get_uio_event_count (struct uio_info_t *info)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  info->event_count = 0;
  snprintf (filename, sizeof (filename), "%s/uio%d/event", UIO_BASE_PATH, info->uio_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "%d", (int *) (&info->event_count));
  fclose (file);
  if (ret < 0)
    return -2;

  return 0;
}

static int
get_uio_mem_addr (struct uio_info_t *info, int map_num)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  info->maps[map_num].addr = UIO_INVALID_ADDR;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/addr", UIO_BASE_PATH, info->uio_num,
	    map_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "0x%lx", &info->maps[map_num].addr);
  fclose (file);
  if (ret < 0)
    return -2;
  return 0;
}

static int
get_uio_mem_name (struct uio_info_t *info, int map_num)
{
  char filename[MAX_FILE_NAME_LEN];

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/name", UIO_BASE_PATH, info->uio_num,
	    map_num);
  return get_uio_line_from_file (filename, info->maps[map_num].name);
}

static int
get_uio_mem_size (struct uio_info_t *info, int map_num)
{
  int ret;
  char filename[MAX_FILE_NAME_LEN];
  FILE *file;

  if (map_num >= MAX_UIO_MAPS)
    return -1;
  info->maps[map_num].size = UIO_INVALID_SIZE;
  snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%d/size", UIO_BASE_PATH, info->uio_num,
	    map_num);
  file = fopen (filename, "r");
  if (!file)
    return -1;
  ret = fscanf (file, "0x%lx", &info->maps[map_num].size);
  fclose (file);
  if (ret < 0)
    return -2;
  return 0;
}

static int
get_uio_name (struct uio_info_t *info)
{
  char filename[MAX_FILE_NAME_LEN];

  snprintf (filename, sizeof (filename), "%s/uio%d/name", UIO_BASE_PATH, info->uio_num);
  return get_uio_line_from_file (filename, info->name);
}

static int
get_uio_version (struct uio_info_t *info)
{
  char filename[MAX_FILE_NAME_LEN];

  snprintf (filename, sizeof (filename), "%s/uio%d/version", UIO_BASE_PATH, info->uio_num);
  return get_uio_line_from_file (filename, info->version);
}

static int
uio_get_all_info (struct uio_info_t *info)
{
  int i;

  if (!info)
    return -1;
  if ((info->uio_num < 0) || (info->uio_num > UIO_MAX_NUM))
    return -1;
  for (i = 0; i < MAX_UIO_MAPS; i++)
    {
      get_uio_mem_size (info, i);
      get_uio_mem_addr (info, i);
      get_uio_mem_name (info, i);
    }
  get_uio_event_count (info);
  get_uio_name (info);
  get_uio_version (info);

  return 0;
}
static struct uio_info_t *
iomem_find_uio_device (const char *name, int index)
{
  char *tmp_name;
  char format_buf[UIO_MAX_FORMAT_SZ];
  int max_str_size = 0;
  struct uio_info_t *uio_info;

  if (name == NULL)
    return 0;

  max_str_size = strlen (UIO_HDR_STR) + strlen (name);
  max_str_size += strlen (UIO_ID_FORMAT_STR) + INT_32_MAX_DEC_STR_SZ + 1;
  tmp_name = clib_mem_alloc_or_null (max_str_size);
  if (!tmp_name)
    {
      pr_err ("no mem for IOMEM-name obj!\n");
      return NULL;
    }
  memset (tmp_name, 0, max_str_size);

  strcpy (format_buf, UIO_HDR_STR);
  if (index < 0)
    snprintf (tmp_name, max_str_size, format_buf, name);
  else
    {
      strcat (format_buf, UIO_ID_FORMAT_STR);
      snprintf (tmp_name, max_str_size, format_buf, name, index);
    }
  uio_info = uio_find_devices_byname (tmp_name);

  pr_debug ("%s: uio_name:%s found:%d\n", __func__, tmp_name, uio_info ? 1 : 0);
  clib_mem_free (tmp_name);
  return uio_info;
}

int
iomem_uio_ioinit (struct mem_uio *uiom, const char *name, int index)
{

  uiom->info = iomem_find_uio_device (name, index);
  if (!uiom->info)
    {
      pr_err ("%s: UIO device not found!\n", __func__);
      return -ENODEV;
    }

  struct uio_info_t *node;

  node = uiom->info;
  while (node)
    {
      uio_get_all_info (node);
      node = node->next;
    }

  return 0;
}
int
iomem_uio_iomap (struct mem_uio *uiom, const char *name, phys_addr_t *pa, void **va)
{
  struct uio_mem_t *mem = NULL;

  mem = uio_find_mem_byname (uiom->info, name);
  if (!mem)
    {
      pr_err ("uio mem region (%s) not found!\n", name);
      return -EINVAL;
    }

  if (mem->fd < 0)
    {
      char dev_name[16];

      snprintf (dev_name, sizeof (dev_name), "/dev/uio%d", mem->info->uio_num);
      mem->fd = open (dev_name, O_RDWR);
    }

  if (mem->fd >= 0)
    {
      *va = uio_single_mmap (mem->info, mem->map_num, mem->fd);
      if (!*va)
	return -EINVAL;

      if (pa)
	*pa = (phys_addr_t) mem->info->maps[mem->map_num].addr;
      iomem_uio_add_entry (&uiom->mem, mem);
    }
  else
    uio_free_mem_info (mem);

  return 0;
}

int
iomem_uio_io_exists (const char *name, int index)
{
  struct uio_info_t *uio_info;

  uio_info = iomem_find_uio_device (name, index);
  return (uio_info != NULL);
}

int
pp2_port_open_uio (struct pp2_port *port)
{
  char *tmp_name;
  char dev_name[16];
  struct uio_info_t *uio_info;
  int fd;
  int max_uio_port_str_size = sizeof (UIO_PORT_STRING) + 8;

  tmp_name = clib_mem_alloc_or_null (max_uio_port_str_size);
  snprintf (tmp_name, max_uio_port_str_size, UIO_PORT_STRING, musdk_port_pp2_id (port),
	    musdk_port_id (port));
  uio_info = uio_find_devices_byname (tmp_name);
  if (!uio_info)
    {
      pr_err ("UIO device (%s) not found!\n", tmp_name);
      if (tmp_name)
	clib_mem_free (tmp_name);
      return -ENODEV;
    }
  if (tmp_name)
    clib_mem_free (tmp_name);
  snprintf (dev_name, sizeof (dev_name), "/dev/uio%d", uio_info->uio_num);
  fd = open (dev_name, O_RDWR);
  if (fd < 0)
    {
      pr_err ("Could not open file (%s)\n", dev_name);
      return errno;
    }
  musdk_port_fd_set (port, fd);
  return 0;
}

static inline void
uio_single_munmap (struct uio_info_t *info, int map_num)
{
  munmap (info->maps[map_num].internal_addr, info->maps[map_num].size);
  info->maps[map_num].mmap_result = UIO_MMAP_NOT_DONE;
}

void
iomem_uio_iodestroy (struct mem_uio *uiom)
{
  uio_free_info (uiom->info);
}

int
pp2_port_close_uio (struct pp2_port *port)
{
  int err;

  err = close (musdk_port_fd (port));
  if (err < 0)
    pr_err (" Could not close file (%s)\n", strerror (errno));
  musdk_port_fd_set (port, -1);
  return err;
}

static void
uio_free_info (struct uio_info_t *info)
{
  struct uio_info_t *p1, *p2;

  p1 = info;
  while (p1)
    {
      uio_free_dev_attrs (p1);
      p2 = p1->next;
      if (p1)
	clib_mem_free (p1);
      p1 = p2;
    }
}

static void
uio_free_dev_attrs (struct uio_info_t *info)
{
  struct uio_dev_attr_t *p1, *p2;

  p1 = info->dev_attrs;
  while (p1)
    {
      p2 = p1->next;
      if (p1)
	clib_mem_free (p1);
      p1 = p2;
    }
  info->dev_attrs = NULL;
}

static void
iomem_uio_add_entry (struct uio_mem_t **headp, struct uio_mem_t *entry)
{
  entry->next = *headp;
  *headp = entry;
}
int
iomem_uio_iounmap (struct mem_uio *uiom, const char *name)
{
  struct uio_mem_t *mem;

  mem = iomem_uio_rm_entry (&uiom->mem, name);
  if (!mem)
    return -ENOENT;
  uio_single_munmap (mem->info, mem->map_num);
  /**
   * TODO
   * Handle device closing if no map registered as mapped. Change file
   * descriptor to -1.
   * If no memory is mapped I don't see any reason to keep the
   * device opened.
   *
   */
  uio_free_mem_info (mem);

  return 0;
}

static struct uio_mem_t *
iomem_uio_rm_entry (struct uio_mem_t **headp, const char *name)
{
  struct uio_mem_t *entry = *headp;
  struct uio_mem_t *node = NULL;

  while (entry)
    {
      if (!strncmp (entry->info->maps[entry->map_num].name, name, UIO_MAX_NAME_SIZE))
	{
	  *headp = entry->next;
	  headp = &*headp;
	  node = entry;
	  return node;
	}

      headp = &entry->next;
      entry = entry->next;
    }
  return node;
}

struct uio_mem_t *
uio_find_mem_byname (struct uio_info_t *info, const char *filter)
{
  struct uio_info_t *infp = info;
  struct uio_mem_t *uiofdp = NULL;

  if (!infp || !filter)
    return NULL;

  while (infp)
    {
      int i;

      for (i = 0; i < MAX_UIO_MAPS; i++)
	{
	  if (strncmp (infp->maps[i].name, filter, UIO_MAX_NAME_SIZE))
	    {
	      continue;
	    }
	  else
	    {
	      uiofdp = mem_calloc (1, sizeof (struct uio_info_t));
	      uiofdp->map_num = i;
	      uiofdp->fd = UIO_INVALID_FD;
	      uiofdp->info = infp;
	      return uiofdp;
	    }
	}
      infp = infp->next;
    }

  return uiofdp;
}

void *
uio_single_mmap (struct uio_info_t *info, int map_num, int fd)
{
  if (!fd)
    return NULL;
  info->maps[map_num].mmap_result = UIO_MMAP_NOT_DONE;
  if (info->maps[map_num].size == UIO_INVALID_SIZE)
    return NULL;
  info->maps[map_num].mmap_result = UIO_MMAP_FAILED;
  info->maps[map_num].internal_addr = mmap (NULL, info->maps[map_num].size, PROT_READ | PROT_WRITE,
					    MAP_SHARED, fd, map_num * getpagesize ());

  if (info->maps[map_num].internal_addr != MAP_FAILED)
    {
      info->maps[map_num].mmap_result = UIO_MMAP_OK;
      return info->maps[map_num].internal_addr;
    }

  return NULL;
}

static void
uio_free_mem_info (struct uio_mem_t *info)
{
  if (info)
    clib_mem_free (info);
  info = NULL;
}
