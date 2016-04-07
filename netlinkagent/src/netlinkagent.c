#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <linux/netlink.h>

#include <errno.h>

#define __USE_GNU
#include <dlfcn.h>

int socket(int domain, int type, int protocol) {
  static int (*socket_real)(int domain, int type, int protocol)=NULL;

  if (!socket_real) socket_real=dlsym(RTLD_NEXT,"socket");

  int fd = socket_real(domain,type,protocol);

  if(domain == AF_NETLINK) {
    char* type_str = NULL;
    if(type == SOCK_DGRAM) {
      type_str = "SOCK_DGRAM";
    } else if (type == SOCK_RAW) {
      type_str = "SOCK_RAW";
    }
    if(type_str) {
      fprintf(stderr,"socket(AF_NETLINK,%s,%i): %i\n",type_str,protocol,fd);
    } else {
      fprintf(stderr,"socket(AF_NETLINK,%i,%i): %i\n",type,protocol,fd);
    }
  } else {
    fprintf(stderr,"socket passthrough\n");
  }

  return fd;
}

int bind (int fd, const struct sockaddr *sk, socklen_t sl) {
  static int (*bind_real)(int fd, const struct sockaddr *sk, socklen_t sl)=NULL;
  if(!bind_real) bind_real=dlsym(RTLD_NEXT,"bind");

  int rv = bind_real(fd,sk,sl);

  fprintf(stderr,"bind(fd=%i...): %i\n",fd,rv);

  return rv;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags)=NULL;
  if(!real_send) real_send = dlsym(RTLD_NEXT,"send");

  fprintf(stderr,"send(fd=%i...,\n",sockfd);
  return real_send(sockfd,buf,len,flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags)=NULL;
  if(!real_recv) real_recv = dlsym(RTLD_NEXT,"recv");

  ssize_t rv = real_recv(sockfd,buf,len,flags);

  fprintf(stderr,"recv(sockfd=%i,buf=%p,len=%zx,flags=%i):%zx",sockfd,buf,len,flags,rv);

  return rv;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags) {
  static ssize_t (*real_recvmsg)(int s, struct msghdr *msg, int flags)=NULL;
  if(!real_recvmsg) real_recvmsg = dlsym(RTLD_NEXT,"recvmsg");
  
  ssize_t rv = real_recvmsg(s,msg,flags);

  fprintf(stderr,"recvmsg(s=%i,msg=%p,flags=%i): rv=%zx\n",s,msg,flags,rv);
  return rv;
}

/* Not quite working yet 
int ioctl(int d, unsigned long request,...) {
  static int (*real_ioctl)(int d, int request, void *argp);
  if(!real_ioctl) real_ioctl = dlsym(RTLD_NEXT,"ioctl");

  struct ifreq *ifr;
  va_list va;

  va_start(va, request);
  ifr = va_arg(va,void *);
  va_end(va);

  int rv = real_ioctl(d,request, ifr);
  fprintf(stderr,"ioctl(fd=%i,request=%lu,ifr=%p): %i\n",d,request,ifr,rv);
  return rv;
}
*/

