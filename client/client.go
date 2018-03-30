package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
)

const (
	joinReq     uint16 = 1
	passReq     uint16 = 2
	passResp    uint16 = 3
	passAccept  uint16 = 4
	data        uint16 = 5
	terminate   uint16 = 6
	reject      uint16 = 7
	hdrSize     int    = 2
	pyldLenSize int    = 4
	packIDSize  int    = 4
)

var (
	nameNPort []string
	passwds   []string
	outfile   string
	aesgcm    cipher.AEAD
	nonce     = make([]byte, 12)
)

func usage() {
	fmt.Printf("Usage: ./client <server name> <server port> <clientpwd1> " +
		"<clientpwd2> <clientpwd3> <output file>\n")
}

func checkError(err error) {
	if err != nil {
		panic("ABORT")
	}
}

func initCipherVariables() cipher.AEAD {
	// Create key from hash of password
	sum := sha256.Sum256([]byte(passwds[0]))
	key := sum[0:]

	// Create cipher block
	block, err := aes.NewCipher(key)
	checkError(err)

	// Wrap cipher block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	checkError(err)

	return gcm
}

func verifyDigest(pk []byte) bool {
	pyldLen := binary.LittleEndian.Uint32(pk[0:])
	recvDigest := pk[4:]
	if int(pyldLen) != len(recvDigest) {
		return false
	}

	data, err := ioutil.ReadFile(outfile)
	checkError(err)

	digest := sha1.Sum(data)

	if len(recvDigest) != len(digest) {
		return false
	}

	for i := 0; i < len(digest); i++ {
		if recvDigest[i] != digest[i] {
			return false
		}
	}

	return true
}

func sendPasswordResponse(conn net.Conn, count int) {
	if count == len(passwds) {
		panic("ABORT")
	}
	passRespLen := hdrSize + pyldLenSize + len(passwds[count])
	pyldLen := uint32(len(passwds[count]))
	response := make([]byte, passRespLen)
	binary.LittleEndian.PutUint16(response[0:], passResp)
	binary.LittleEndian.PutUint32(response[2:], pyldLen)
	copy(response[6:], []byte(passwds[count]))
	ct := encrypt(response)
	_, err := conn.Write(ct)
	checkError(err)
}

func sendJoinRequest(conn net.Conn) {
	// Send the nonce as payload with JOIN_REQ packet
	packLen := hdrSize + pyldLenSize + len(nonce)
	pyldLen := uint32(len(nonce))
	packet := make([]byte, packLen)
	binary.LittleEndian.PutUint16(packet[0:], joinReq)
	binary.LittleEndian.PutUint32(packet[2:], pyldLen)
	copy(packet[6:], nonce)
	_, err := conn.Write(packet)
	checkError(err)
}

func encrypt(pt []byte) []byte {
	ct := aesgcm.Seal(nil, nonce, pt, nil)
	return ct
}

func decrypt(ct []byte) []byte {
	pt, err := aesgcm.Open(nil, nonce, ct, nil)
	checkError(err)
	return pt
}

func handleConnection(conn net.Conn) bool {
	sendJoinRequest(conn)

	buff := make([]byte, 1010)

	passCount := 0

	f, err := os.Create(outfile)
	defer f.Close()
	checkError(err)

	// Read responses
	for {
		n, err := conn.Read(buff)
		checkError(err)
		pt := decrypt(buff[0:n])
		header := binary.LittleEndian.Uint16(pt[0:])

		switch header {
		case passReq:
			sendPasswordResponse(conn, passCount)
			passCount++
		case passAccept:
			//TODO Not sure if there is an action to take here
		case data:
			// pkID := binary.LittleEndian.Uint32(buff[6:10])
			// pyldLen := binary.LittleEndian.Uint32(pt[2:6])
			data := pt[10:]
			_, err := f.Write(data)
			checkError(err)
			f.Sync()
		case reject:
			return false
		case terminate:
			return verifyDigest(pt[2:])
		default:
			return false
		}
	}
}

func main() {
	args := os.Args
	if len(args) != 7 {
		usage()
		return
	}

	// Parse command line args
	nameNPort = args[1:3]
	passwds = args[3:6]
	outfile = args[6]

	_, err := strconv.Atoi(nameNPort[1])
	if err != nil {
		usage()
		return
	}

	// Fill nonce with random bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		checkError(err)
	}

	aesgcm = initCipherVariables()

	// Connect to server
	hostPort := nameNPort[0] + ":" + nameNPort[1]
	conn, err := net.Dial("udp4", hostPort)
	defer conn.Close()
	checkError(err)

	if handleConnection(conn) == true {
		fmt.Println("OK")
	} else {
		fmt.Println("ABORT")
	}
}
