/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <musdk_internal.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "musdk-uio",
};

#define UIO_BASE_PATH "/sys/class/uio"
#define UIO_MAX_MAPS  5
#define UIO_NAME_SIZE 64

static int
uio_read_line (const char *filename, char *line)
{
  FILE *file;
  char *p;

  file = fopen (filename, "r");
  if (!file)
    return -1;

  p = fgets (line, UIO_NAME_SIZE, file);
  fclose (file);
  if (!p)
    return -1;

  p = strchr (line, '\n');
  if (p)
    *p = 0;
  return 0;
}

static int
uio_read_ulong (const char *filename, unsigned long *value)
{
  FILE *file;
  int rv;

  file = fopen (filename, "r");
  if (!file)
    return -1;
  rv = fscanf (file, "0x%lx", value);
  fclose (file);
  return rv == 1 ? 0 : -1;
}

static int
uio_find_device (vnet_dev_t *dev, const char *name, int index)
{
  char filename[PATH_MAX];
  char uio_name[UIO_NAME_SIZE];
  char target[UIO_NAME_SIZE];
  struct dirent *entry;
  DIR *dir;
  int uio_num = -1;

  if (index < 0)
    snprintf (target, sizeof (target), "uio_%s", name);
  else
    snprintf (target, sizeof (target), "uio_%s_%d", name, index);

  dir = opendir (UIO_BASE_PATH);
  if (!dir)
    {
      log_err (dev, "cannot open %s: %s", UIO_BASE_PATH, strerror (errno));
      return -1;
    }

  while ((entry = readdir (dir)))
    {
      char extra;
      int n;

      if (sscanf (entry->d_name, "uio%d%c", &n, &extra) != 1)
	continue;
      snprintf (filename, sizeof (filename), "%s/%s/name", UIO_BASE_PATH, entry->d_name);
      if (uio_read_line (filename, uio_name) == 0 && strcmp (uio_name, target) == 0)
	{
	  uio_num = n;
	  break;
	}
    }
  closedir (dir);

  log_debug (dev, "UIO device %s found:%u", target, uio_num >= 0);
  return uio_num;
}

static int
uio_find_map (int uio_num, const char *map_name, u32 *size)
{
  char filename[PATH_MAX];
  char name[UIO_NAME_SIZE];
  unsigned long map_size;

  for (u32 i = 0; i < UIO_MAX_MAPS; i++)
    {
      snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%u/name", UIO_BASE_PATH, uio_num, i);
      if (uio_read_line (filename, name))
	continue;
      if (strcmp (name, map_name))
	continue;
      snprintf (filename, sizeof (filename), "%s/uio%d/maps/map%u/size", UIO_BASE_PATH, uio_num, i);
      if (uio_read_ulong (filename, &map_size))
	return -1;
      *size = map_size;
      return i;
    }
  return -1;
}

vnet_dev_rv_t
mvpp2_uio_init (vnet_dev_t *dev, int *uio_num)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  char dev_name[32];

  md->uio_fd = -1;
  *uio_num = uio_find_device (dev, "pp", md->pp_id);
  if (*uio_num < 0)
    {
      log_err (dev, "UIO device uio_pp_%u not found", md->pp_id);
      return VNET_DEV_ERR_NOT_FOUND;
    }

  snprintf (dev_name, sizeof (dev_name), "/dev/uio%d", *uio_num);
  md->uio_fd = open (dev_name, O_RDWR);
  if (md->uio_fd < 0)
    {
      log_err (dev, "cannot open %s: %s", dev_name, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_uio_map (vnet_dev_t *dev, int uio_num, const char *name, u32 *size, void **va)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  int map_index;
  void *addr;

  map_index = uio_find_map (uio_num, name, size);
  if (map_index < 0 || !*size)
    return VNET_DEV_ERR_NOT_FOUND;

  addr =
    mmap (0, *size, PROT_READ | PROT_WRITE, MAP_SHARED, md->uio_fd, map_index * getpagesize ());
  if (addr == MAP_FAILED)
    {
      log_err (dev, "cannot map UIO memory region %s: %s", name, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }

  *va = addr;
  return VNET_DEV_OK;
}

u8
mvpp2_uio_exists (vnet_dev_t *dev, u8 pp_id)
{
  return uio_find_device (dev, "pp", pp_id) >= 0;
}

void
mvpp2_uio_deinit (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  if (md->pp_base)
    munmap ((void *) md->pp_base, md->pp_map_size);
  if (md->gop_hw_mspg)
    munmap ((void *) md->gop_hw_mspg, md->mspg_map_size);
  if (md->cm3_base)
    munmap ((void *) md->cm3_base, md->cm3_map_size);
  if (md->uio_fd >= 0)
    close (md->uio_fd);
  md->uio_fd = -1;
}
