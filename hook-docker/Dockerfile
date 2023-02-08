# syntax=docker/dockerfile:experimental

FROM golang:1.17-alpine as dev
ENV HTTP_PROXY=http://10.134.141.235:3128
ENV HTTPS_PROXY=http://10.134.141.235:3128
COPY . /src/
WORKDIR /src
ENV GO111MODULE=on
RUN --mount=type=cache,sharing=locked,id=gomod,target=/go/pkg/mod/cache \
    --mount=type=cache,sharing=locked,id=goroot,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -a -ldflags '-w -extldflags "-static"' -o /hook-docker

FROM docker:20.10.15-dind
ENV HTTP_PROXY=http://10.134.141.235:3128
ENV HTTPS_PROXY=http://10.134.141.235:3128
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN apk update; apk add kexec-tools
COPY --from=dev /hook-docker .
ENTRYPOINT ["/hook-docker"]
