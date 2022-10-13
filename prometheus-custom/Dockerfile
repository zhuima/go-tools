FROM golang:alpine AS builder
RUN apk update && apk add --no-cache git
COPY src $GOPATH/src/zhiminwen/hpasimulator
WORKDIR $GOPATH/src/zhiminwen/hpasimulator
RUN go get -d -v
RUN go build -o /tmp/simulator *.go
FROM alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup && mkdir -p /app 
COPY --from=builder /tmp/simulator /app
RUN chmod a+rx /app/simulator
USER appuser
WORKDIR /app
ENV LISTENING_PORT 8080
CMD ["./simulator"]