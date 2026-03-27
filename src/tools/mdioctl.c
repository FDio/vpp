/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/mii.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MDIO_PHY_ID_C45 0x8000

static void
usage (char *prog)
{
  fprintf (stderr,
	   "Usage:\n"
	   "  %s phy <dev> <phy-index>\n"
	   "  %s read <dev> <phy-addr> <reg>\n"
	   "  %s write <dev> <phy-addr> <reg> <value>\n"
	   "  %s read45 <dev> <prtad> <devad> <reg>\n"
	   "  %s write45 <dev> <prtad> <devad> <reg> <value>\n"
	   "  %s dump <dev> <phy-index>\n",
	   prog, prog, prog, prog, prog, prog);
}

static int
parse_u32 (char *s, uint32_t *v)
{
  char *end = 0;
  unsigned long x;

  errno = 0;
  x = strtoul (s, &end, 0);
  if (errno || end == s || *end != 0 || x > 0xffffffffu)
    return -1;

  *v = x;
  return 0;
}

static uint16_t
mdio_phy_id_c45 (uint16_t prtad, uint16_t devad)
{
  return MDIO_PHY_ID_C45 | ((prtad & 0x1f) << 5) | (devad & 0x1f);
}

static int
mdio_do_ioctl (int fd, uint16_t phy_id, uint16_t reg_num, uint16_t val_in, unsigned int cmd,
	       uint16_t *val_out)
{
  struct ifreq ifr = {};
  struct mii_ioctl_data *mii;
  int rv;

  mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
  mii->phy_id = phy_id;
  mii->reg_num = reg_num;
  mii->val_in = val_in;

  rv = ioctl (fd, cmd, &ifr);
  if (rv < 0)
    return -1;

  if (val_out)
    *val_out = mii->val_out;

  return 0;
}

static int
mdio_get_phy_addr (int fd, uint16_t phy_index, uint16_t *phy_addr)
{
  struct ifreq ifr = {};
  struct mii_ioctl_data *mii;
  int rv;

  mii = (struct mii_ioctl_data *) &ifr.ifr_ifru;
  mii->val_in = phy_index;

  rv = ioctl (fd, SIOCGMIIPHY, &ifr);
  if (rv < 0)
    return -1;

  *phy_addr = mii->phy_id;
  return 0;
}

static void
dump_basic (int fd, uint16_t phy_index)
{
  uint16_t phy_addr;
  uint16_t bmcr;
  uint16_t bmsr;
  uint16_t physid1;
  uint16_t physid2;

  if (mdio_get_phy_addr (fd, phy_index, &phy_addr) < 0)
    {
      perror ("SIOCGMIIPHY");
      exit (1);
    }

  if (mdio_do_ioctl (fd, phy_addr, MII_BMCR, 0, SIOCGMIIREG, &bmcr) < 0)
    {
      perror ("SIOCGMIIREG BMCR");
      exit (1);
    }

  if (mdio_do_ioctl (fd, phy_addr, MII_BMSR, 0, SIOCGMIIREG, &bmsr) < 0)
    {
      perror ("SIOCGMIIREG BMSR");
      exit (1);
    }

  if (mdio_do_ioctl (fd, phy_addr, MII_PHYSID1, 0, SIOCGMIIREG, &physid1) < 0)
    {
      perror ("SIOCGMIIREG PHYSID1");
      exit (1);
    }

  if (mdio_do_ioctl (fd, phy_addr, MII_PHYSID2, 0, SIOCGMIIREG, &physid2) < 0)
    {
      perror ("SIOCGMIIREG PHYSID2");
      exit (1);
    }

  printf ("phy-index %u phy-addr 0x%x\n", phy_index, phy_addr);
  printf ("BMCR    0x%04x reset%c loopback%c an-enable%c an-restart%c full-duplex%c"
	  " speed100%c speed1000%c\n",
	  bmcr, (bmcr & BMCR_RESET) ? '+' : '-', (bmcr & BMCR_LOOPBACK) ? '+' : '-',
	  (bmcr & BMCR_ANENABLE) ? '+' : '-', (bmcr & BMCR_ANRESTART) ? '+' : '-',
	  (bmcr & BMCR_FULLDPLX) ? '+' : '-', (bmcr & BMCR_SPEED100) ? '+' : '-',
	  (bmcr & BMCR_SPEED1000) ? '+' : '-');
  printf ("BMSR    0x%04x link%c an-cap%c an-done%c rfault%c 10h%c 10f%c 100h%c 100f%c\n", bmsr,
	  (bmsr & BMSR_LSTATUS) ? '+' : '-', (bmsr & BMSR_ANEGCAPABLE) ? '+' : '-',
	  (bmsr & BMSR_ANEGCOMPLETE) ? '+' : '-', (bmsr & BMSR_RFAULT) ? '+' : '-',
	  (bmsr & BMSR_10HALF) ? '+' : '-', (bmsr & BMSR_10FULL) ? '+' : '-',
	  (bmsr & BMSR_100HALF) ? '+' : '-', (bmsr & BMSR_100FULL) ? '+' : '-');
  printf ("PHYSID  0x%04x 0x%04x\n", physid1, physid2);
}

int
main (int argc, char **argv)
{
  char *cmd;
  char *dev;
  int fd;
  uint32_t a0;
  uint32_t a1;
  uint32_t a2;
  uint32_t a3;
  uint16_t value;

  if (argc < 4)
    {
      usage (argv[0]);
      return 1;
    }

  cmd = argv[1];
  dev = argv[2];
  fd = open (dev, O_RDWR);
  if (fd < 0)
    {
      perror (dev);
      return 1;
    }

  if (strcmp (cmd, "phy") == 0)
    {
      if (argc != 4 || parse_u32 (argv[3], &a0) < 0)
	goto bad_args;
      if (mdio_get_phy_addr (fd, a0, &value) < 0)
	{
	  perror ("SIOCGMIIPHY");
	  close (fd);
	  return 1;
	}
      printf ("0x%x\n", value);
    }
  else if (strcmp (cmd, "read") == 0)
    {
      if (argc != 5 || parse_u32 (argv[3], &a0) < 0 || parse_u32 (argv[4], &a1) < 0)
	goto bad_args;
      if (mdio_do_ioctl (fd, a0, a1, 0, SIOCGMIIREG, &value) < 0)
	{
	  perror ("SIOCGMIIREG");
	  close (fd);
	  return 1;
	}
      printf ("0x%04x\n", value);
    }
  else if (strcmp (cmd, "write") == 0)
    {
      if (argc != 6 || parse_u32 (argv[3], &a0) < 0 || parse_u32 (argv[4], &a1) < 0 ||
	  parse_u32 (argv[5], &a2) < 0)
	goto bad_args;
      if (mdio_do_ioctl (fd, a0, a1, a2, SIOCSMIIREG, 0) < 0)
	{
	  perror ("SIOCSMIIREG");
	  close (fd);
	  return 1;
	}
    }
  else if (strcmp (cmd, "read45") == 0)
    {
      if (argc != 6 || parse_u32 (argv[3], &a0) < 0 || parse_u32 (argv[4], &a1) < 0 ||
	  parse_u32 (argv[5], &a2) < 0)
	goto bad_args;
      if (mdio_do_ioctl (fd, mdio_phy_id_c45 (a0, a1), a2, 0, SIOCGMIIREG, &value) < 0)
	{
	  perror ("SIOCGMIIREG");
	  close (fd);
	  return 1;
	}
      printf ("0x%04x\n", value);
    }
  else if (strcmp (cmd, "write45") == 0)
    {
      if (argc != 7 || parse_u32 (argv[3], &a0) < 0 || parse_u32 (argv[4], &a1) < 0 ||
	  parse_u32 (argv[5], &a2) < 0 || parse_u32 (argv[6], &a3) < 0)
	goto bad_args;
      if (mdio_do_ioctl (fd, mdio_phy_id_c45 (a0, a1), a2, a3, SIOCSMIIREG, 0) < 0)
	{
	  perror ("SIOCSMIIREG");
	  close (fd);
	  return 1;
	}
    }
  else if (strcmp (cmd, "dump") == 0)
    {
      if (argc != 4 || parse_u32 (argv[3], &a0) < 0)
	goto bad_args;
      dump_basic (fd, a0);
    }
  else
    goto bad_args;

  close (fd);
  return 0;

bad_args:
  usage (argv[0]);
  close (fd);
  return 1;
}
