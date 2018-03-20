package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
)

const (
	JoinReq     uint16 = 1
	PassReq     uint16 = 2
	PassResp    uint16 = 3
	PassAccept  uint16 = 4
	Data        uint16 = 5
	Terminate   uint16 = 6
	Reject      uint16 = 7
	HdrSize     int    = 2
	PyldLenSize int    = 4
	PackIdSize  int    = 4
)

var (
	nameNPort  []string
	passwds    []string
	outfile    string
	joinReqArr = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func usage() {
	fmt.Printf("Usage: ./client <server name> <server port> <clientpwd1> <clientpwd2> <clientpwd3> <output file>\n")
}

func checkError(err error) {
	if err != nil {
		panic("ABORT")
	}
}

func verifyDigest(pk []byte) {
	pyldLen := binary.LittleEndian.Uint32(pk[0:])
	recvDigest := pk[4:]
	if int(pyldLen) != len(recvDigest) {
		fmt.Println("ABORT")
		return
	}

	data, err := ioutil.ReadFile(outfile)
	checkError(err)

	digest := sha1.Sum(data)

	if len(recvDigest) != len(digest) {
		fmt.Println("ABORT")
		return
	}

	for i := 0; i < len(digest); i++ {
		if recvDigest[i] != digest[i] {
			fmt.Println("ABORT")
			return
		}
	}

	fmt.Println("OK")
}

func handleConnection(conn net.Conn) {
	// Send Join Request
	conn.Write(joinReqArr)

	buff := make([]byte, 1010)

	passCount := 0

	f, err := os.Create(outfile)
	defer f.Close()
	checkError(err)

	// Read responses
	for {
		n, err := conn.Read(buff)
		checkError(err)
		header := binary.LittleEndian.Uint16(buff[0:])

		switch header {
		case PassReq:
			passRespLen := HdrSize + PyldLenSize + len(passwds[passCount])
			pyldLen := uint32(len(passwds[passCount]))
			response := make([]byte, passRespLen)
			binary.LittleEndian.PutUint16(response[0:], PassResp)
			binary.LittleEndian.PutUint32(response[2:], pyldLen)
			copy(response[6:], []byte(passwds[passCount]))
			_, err := conn.Write(response)
			checkError(err)
			passCount++
		case PassAccept:
			//TODO Not sure if there is an action to take here
		case Data:
			// pkID := binary.LittleEndian.Uint32(buff[6:10])
			data := buff[10:n]
			_, err := f.Write(data)
			checkError(err)
			f.Sync()
		case Reject:
			fmt.Println("ABORT")
			return
		case Terminate:
			verifyDigest(buff[2:n])
			return
		default:
			fmt.Println("ABORT")
			return
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

	// Connect to server
	hostPort := nameNPort[0] + ":" + nameNPort[1]
	conn, err := net.Dial("udp4", hostPort)
	defer conn.Close()
	checkError(err)

	handleConnection(conn)
}
