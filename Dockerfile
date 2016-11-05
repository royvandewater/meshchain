FROM golang:1.6
MAINTAINER Octoblu, Inc. <docker@octoblu.com>

WORKDIR /go/src/github.com/octoblu/meshchain
COPY . /go/src/github.com/octoblu/meshchain

RUN env CGO_ENABLED=0 go build -o meshchain -a -ldflags '-s' .

CMD ["./meshchain"]
