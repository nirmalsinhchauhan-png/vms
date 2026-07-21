# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vms-backend ./cmd/api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && \
    addgroup -S vms && adduser -S vms -G vms

COPY --from=builder /out/vms-backend /usr/local/bin/vms-backend

USER vms
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/vms-backend"]
