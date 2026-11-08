FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /proxy ./cmd/proxy

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 proxy && adduser -D -H -u 10001 -G proxy proxy
COPY --from=build /proxy /usr/local/bin/proxy
USER 10001:10001
LABEL org.opencontainers.image.source="https://github.com/Cipher7788/anonymity-proxy"
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/proxy"]
