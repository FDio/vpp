# Run from top of vpp repo with command:
# docker build -f extras/docker/build/Dockerfile.centos7 .
FROM centos:7.3.1611
ARG REPO=master
COPY . /vpp
WORKDIR /vpp
RUN curl -s https://packagecloud.io/install/repositories/fdio/${REPO}/script.rpm.sh |  bash
RUN yum install -y vpp-dpdk-devel make sudo
RUN UNATTENDED=y make install-dep
RUN make pkg-rpm
CMD ["/bin/bash"]