# Run from top of vpp repo with command:
# docker build -f extras/rpm/opensuse/Dockerfile .

ARG SUSE_VERSION=15.3

FROM opensuse/leap:${SUSE_VERSION} as vppbuild
COPY . /vpp
WORKDIR /vpp
RUN zypper install -y make sudo
COPY . .
RUN UNATTENDED=y make install-dep
RUN ln -s /usr/bin/cmake /usr/bin/cmake3
RUN UNATTENDED=y make install-ext-deps
RUN make pkg-rpm
CMD ["/bin/bash"]
