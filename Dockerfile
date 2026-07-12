FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/elvanto-broker ./cmd/elvanto-broker

FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data

COPY --from=build /out/elvanto-broker /usr/local/bin/elvanto-broker

USER appuser

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/elvanto-broker"]
