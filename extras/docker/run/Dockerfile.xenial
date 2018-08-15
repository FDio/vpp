FROM ubuntu:xenial
ARG DEBIAN_FRONTEND=noninteractive
ARG REPO=release
RUN apt-get update
RUN apt-get -y install curl
RUN curl -s https://packagecloud.io/install/repositories/fdio/${REPO}/script.deb.sh |  bash
RUN apt-get update
RUN apt-get -y install vpp vpp-plugins
RUN apt-get -y purge curl
RUN apt-get -y clean
CMD ["/usr/bin/vpp","-c","/etc/vpp/startup.conf"]

