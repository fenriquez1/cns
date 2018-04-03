FROM golang:1.8

WORKDIR /go/src/server
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 8080:8080/udp
CMD [ "server", "8080", "password", "sendfile.txt" ]
