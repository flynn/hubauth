FROM golang:1.14rc1-alpine

WORKDIR /app

COPY . .
RUN go build -o app

CMD ["/app/app"]
