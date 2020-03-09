FROM golang:1.14-alpine AS builder

WORKDIR /app
COPY . .
RUN go build ./cmd/hubauth-ext && go build ./cmd/hubauth-int

FROM alpine:latest

COPY --from=builder /app/hubauth-ext /app/hubauth-int /app/
