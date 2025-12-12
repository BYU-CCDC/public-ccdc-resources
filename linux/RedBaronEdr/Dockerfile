FROM golang:1.23.4

RUN apt update
RUN apt install -y libmagic-dev automake libtool make gcc pkg-config
WORKDIR /tmp

ADD https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.2.tar.gz /tmp/yara.tar.gz

RUN tar -zxf yara.tar.gz
WORKDIR /tmp/yara-4.5.2/
RUN ./bootstrap.sh
RUN ./configure && make && make install
RUN rm -rf /tmp/*

WORKDIR /build

RUN apt install libssl-dev libjansson-dev zlib1g-dev liblzma-dev libbz2-dev -y

ADD go.mod .

RUN go mod download

ADD . .

RUN go build -ldflags '-extldflags "-static -lyara -lssl -lcrypto -ljansson -lmagic -lz -llzma -lbz2 -lm -lpthread -lresolv"' -tags yara_static -o red .
