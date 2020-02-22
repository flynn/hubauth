FROM golang:1.14rc1-alpine

WORKDIR /app

COPY . .
RUN go build ./cmd/hubauth-ext && go build ./cmd/hubauth-int
