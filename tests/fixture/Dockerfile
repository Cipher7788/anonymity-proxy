FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY tests/fixture ./tests/fixture
RUN CGO_ENABLED=0 go build -trimpath -o /origin ./tests/fixture
FROM alpine:3.23
COPY --from=build /origin /origin
USER 10001:10001
ENTRYPOINT ["/origin"]
