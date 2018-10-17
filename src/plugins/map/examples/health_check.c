#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdbool.h>
#include <errno.h>

static void
usage (void) {
  fprintf(stderr,
	  "Usage: health_check"
	  " -d debug"
	  " -I interface"
	  "\n");
  exit(2);
}

int
main (int argc, char **argv)
{
  int sd, ch;
  uint8_t *opt, *pkt;
  struct ifreq ifr;
  char *interface = NULL;
  bool debug = false;

  while ((ch = getopt(argc, argv, "h?" "I:" "d")) != EOF) {
    switch(ch) {
    case 'I':
      interface = optarg;
      break;
    case 'd':
      debug = true;
      break;
    default:
      usage();
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (!interface)
    usage();

  /* Request a socket descriptor sd. */
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_IPIP)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
  }

  clib_memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

  /* Bind socket to interface of this node. */
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }
  if (debug) printf("Binding to interface %s\n", interface);

  while (1) {
    struct sockaddr_in6 src_addr;
    socklen_t addrlen = sizeof(src_addr);
    char source[INET6_ADDRSTRLEN+1];
    int len;
    uint8_t inpack[IP_MAXPACKET];

    if ((len = recvfrom(sd, inpack, sizeof(inpack), 0, (struct sockaddr *)&src_addr, &addrlen)) < 0) {
      perror("recvfrom failed ");
    }
    if (inet_ntop(AF_INET6, &src_addr.sin6_addr, source, INET6_ADDRSTRLEN) == NULL) {
      perror("inet_ntop() failed.");
      exit(EXIT_FAILURE);
    }

    /* Reply */
    struct iphdr *ip = (struct iphdr *)inpack;
    uint32_t saddr;
    struct icmphdr *icmp;

    saddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = saddr;

    switch (ip->protocol) {
    case 1:
      if (debug) printf ("ICMP Echo request from %s\n", source);
      icmp = (struct icmphdr *)&ip[1];
      icmp->type = ICMP_ECHOREPLY;
      break;
    default:
      fprintf(stderr, "Unsupported protocol %d", ip->protocol);
    }
    if (len = sendto(sd, inpack, len, 0, (struct sockaddr *)&src_addr, addrlen) < 0) {
      perror("sendto failed ");
    }
  }

  close (sd);

  return (EXIT_SUCCESS);
}
