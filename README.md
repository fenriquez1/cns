# cns
Client and Server project using Go

This project implements UDP client-server encrypted communication. It is only for proof of concept.

The client sends a join request with a nonce (number used only once) as a payload to the server. The nonce will be used as the initialization vector (IV) passed to the encryption algorithm. Following the join request, all communication will be encrypted with the nonce and the password using AES256. Upon successful password authentication, the server will send a file to the client and a sha1 checksum of the file. Then, the client will verify that the checksum produced from the received file matches the checksum received from the server. Both client and server print 'OK' to the terminal upon successful execution. 

# Running in Docker
Build server image:
	‘docker build -t my-server-image ./server/
	
Build client image:
	‘docker build -t my-client-image ./client/
	
Run server:
	‘docker run -it --rm -p 8080:8080/udp --name my-server-container my-server-image’
	
Run client:
	‘docker run -it --rm --net=host --name my-client-container my-client-image’
