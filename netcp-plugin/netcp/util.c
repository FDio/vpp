#include "netcp.h"

static u64 rnd_pagesize(u64 size)
{
  static u64 pagesize;
  u64 rv;

  if (pagesize == 0)
    pagesize = getpagesize();

  rv = (size + (pagesize-1)) & ~(pagesize-1);
  return(rv);
}


/*
 * map_file
 * typical mmap action
 */
u8 * map_file (u8 *filename, u64 *sizep, int is_write)
{
  struct stat statb;
  int fd;
  u8 zero = 0;
  u64 map_size;
  u8 * rv;
    
  ASSERT(sizep);

  if (is_write)
    {
      fd = open ((char *) filename, O_RDWR | O_CREAT, 0777);
      if (fd < 0)
        {
          clib_unix_warning ("Couldn't create %s", filename);
          return 0;
        }
      
      lseek (fd, *sizep, SEEK_SET);
      if (write (fd, &zero, 1) != 1)
        clib_unix_warning ("set file size");

      map_size = rnd_pagesize (*sizep);

      rv = mmap (0, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
      if (rv == (u8 *)MAP_FAILED)
        rv = 0;
      close(fd);
    }
  else
    {
      fd = open ((char *) filename, O_RDONLY);
      if (fd < 0)
        {
          clib_unix_warning ("Couldn't read %s", filename);
          return 0;
        }

      if (fstat (fd, &statb) < 0)
        {
          clib_unix_warning ("Couldn't stat %s", filename);
          close(fd);
          return 0;
        }

      /* Don't try to mmap directories, FIFOs, semaphores, etc. */
      if (! (statb.st_mode & S_IFREG)) 
        {
          clib_warning ("%s is not a regular file", filename);
          close (fd);
          return 0;
        }
        
      if (statb.st_size < 3)
        {
          clib_warning ("%s is empty", filename);
          close (fd);
          return 0;
        }

      *sizep = statb.st_size;

      map_size = rnd_pagesize (statb.st_size);

      rv = mmap (0, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
      if (rv == (u8 *)MAP_FAILED)
        rv = 0;
      close(fd);
    }
  return rv;
}

void unmap_file (u8 * filename, u8 * addr, u64 size)
{
  int rv;
  u64 rnd_size;

  rnd_size = rnd_pagesize (size);

  rv = munmap (addr, rnd_size);

  if (rv < 0)
    clib_unix_warning ("munmap");

  rv = truncate ((char *) filename, size);

  if (rv < 0)
    clib_unix_warning ("truncate");
  return rv;
}
