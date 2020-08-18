FROM golang:1.15-buster AS builder

WORKDIR /app
COPY . .
RUN go build ./cmd/hubauth-ext && go build ./cmd/hubauth-int

FROM gcr.io/distroless/base-debian10

COPY --from=builder /app/hubauth-ext /app/hubauth-int /app/
