FROM golang:alpine AS build
RUN mkdir /build 
ADD . /build/
WORKDIR /build 
RUN apk add git && go build -o bouncer ./cmd/alertmanager_bouncer

FROM alpine
COPY --from=build /build/bouncer /bouncer/bouncer
RUN adduser -S -D -H -h /bouncer bouncer && chown bouncer: /bouncer/bouncer && chmod +x /bouncer/bouncer
USER bouncer
ENTRYPOINT ["/bouncer/bouncer"]