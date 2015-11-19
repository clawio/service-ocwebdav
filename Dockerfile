FROM golang:1.5
MAINTAINER Hugo González Labrador

ENV CLAWIO_OCWEBDAV_PORT 57004
ENV CLAWIO_OCWEBDAV_AUTH "service-auth:57000"
ENV CLAWIO_OCWEBDAV_META "service-localstore-meta:57001"
ENV CLAWIO_OCWEBDAV_DATA "http://service-localstore-data:57002"
ENV CLAWIO_SHAREDSECRET secret

ADD . /go/src/github.com/clawio/service.ocwebdav
WORKDIR /go/src/github.com/clawio/service.ocwebdav

RUN go get -u github.com/tools/godep
RUN godep restore
RUN go install

ENTRYPOINT /go/bin/service.ocwebdav

EXPOSE 57004

