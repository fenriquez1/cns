# cns
Client and Server project using Go

This project implements UDP client-server communication. Upon successful password authentication, the server will send a file to the client and a sha1 checksum of the file. Then, the client will verify that the checksum produced from the received file matches the checksum received from the server.
