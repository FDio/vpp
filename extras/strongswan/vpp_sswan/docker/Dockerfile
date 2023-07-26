FROM    jrei/systemd-ubuntu:20.04

# add proxy according your own network
#ENV	http_proxy=""
#ENV	https_proxy=""
#ENV	no_proxy=""

# update
RUN	apt-get update

# tools
RUN	apt-get install -y git make wget libsystemd-dev
RUN	apt-get install -y sudo gperf bison flex
RUN	apt-get install -y iproute2 iputils-ping

# setup env
WORKDIR /root
COPY    ./docker/scripts/init_docker1.sh /root/
COPY    ./docker/scripts/init_docker2.sh /root/
COPY    ./docker/scripts/init.sh /root/
COPY    ./docker/scripts/run_vpp.sh /root/
RUN     chmod +x /root/init_docker1.sh
RUN     chmod +x /root/init_docker2.sh
RUN     chmod +x /root/init.sh
RUN     chmod +x /root/run_vpp.sh

# only for testing, should be deleted after merged this patch
COPY    / /root/vpp_sswan

RUN     ./init.sh
