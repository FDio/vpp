# Run from top of vpp repo with command:
# docker build -f extras/docker/build/Dockerfile.bionic .
FROM ubuntu:bionic
ARG REPO=master
COPY . /vpp
WORKDIR /vpp
RUN apt-get update
RUN apt-get -y install make sudo git curl
RUN curl -s https://packagecloud.io/install/repositories/fdio/${REPO}/script.deb.sh |  bash
RUN apt-get update
RUN apt-get -y install vpp-dpdk-dev
RUN UNATTENDED=y make install-dep
RUN make pkg-deb
CMD ["/bin/bash"]