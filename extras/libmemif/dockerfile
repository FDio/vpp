FROM ubuntu:xenial

RUN apt-get update && \
	apt-get install -y git build-essential autoconf pkg-config libtool sudo check
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir /libmemif
ADD . /libmemif
WORKDIR /libmemif

RUN ./bootstrap
RUN ./configure
RUN make
RUN make install

RUN mkdir /run/vpp

RUN ulimit -c unlimited

CMD ./.libs/icmpr-epoll
