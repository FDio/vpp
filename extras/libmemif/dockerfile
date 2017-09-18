FROM ubuntu:xenial

RUN apt-get update && \
	apt-get install -y git build-essential autoconf pkg-config libtool sudo check
RUN rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/JakubGrajciar/libmemif.git /libmemif
WORKDIR /libmemif
RUN git checkout master
RUN ./bootstrap
RUN ./configure
RUN make
RUN make install

RUN mkdir /var/vpp

RUN ulimit -c unlimited

CMD ./.libs/icmpr-epoll
