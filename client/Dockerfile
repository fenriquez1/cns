FROM golang:1.8

WORKDIR /go/src/client
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD [ "client", "localhost", "8080", "password", "p2", "p3", "infile.txt" ]
