FROM golang:1.25.0-alpine as build
MAINTAINER luankz
WORKDIR /app
COPY . .
RUN go mod tidy
ARG VERSION=unknown
RUN go build -ldflags="-X main.version=${VERSION} -w -s" -a -o dist/eiam main.go
FROM alpine:latest as deploy
ENV EGO_DEBUG=true
WORKDIR /app
COPY --from=build /app/dist/eiam .
EXPOSE 8000
ENTRYPOINT ["./eiam", "start"]