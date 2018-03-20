package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	JoinReq     uint16 = 1
	PassReq     uint16 = 2
	PassResp    uint16 = 3
	PassAaccept uint16 = 4
	Data        uint16 = 5
	Terminate   uint16 = 6
	Reject      uint16 = 7
	HdrSize     int    = 2
	PyldLenSize int    = 4
	PackIdSize  int    = 4
)

var (
	clientPassword string
	inputFilePath  string
	passReqArr     = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	passAccArr     = []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	rejectArr      = []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func usage() {
	fmt.Printf("Usage: ./server <port> <password> <input file>\n")
}

func checkError(err error) {
	if err != nil {
		panic("ABORT")
	}
}

func terminate(pc net.PacketConn, addr net.Addr) {
	// Get digest and send terminate packet
	data, err := ioutil.ReadFile(inputFilePath)
	checkError(err)
	digest := sha1.Sum(data)

	packLen := HdrSize + PyldLenSize + sha1.Size
	pack := make([]byte, packLen)
	binary.LittleEndian.PutUint16(pack[0:], Terminate)
	binary.LittleEndian.PutUint32(pack[2:], uint32(len(digest)))
	copy(pack[6:], digest[0:])
	pc.WriteTo(pack, addr)
	fmt.Println("OK")
}

func sendFile(pc net.PacketConn, addr net.Addr) {
	// Read file and send
	f, err := os.Open(inputFilePath)
	defer f.Close()
	checkError(err)

	fi, err := f.Stat()
	checkError(err)

	dat := make([]byte, 1000)
	s := fi.Size()
	packID := uint32(0)
	for i := int64(0); i < s; {
		n, err := f.Read(dat)
		checkError(err)
		packLen := HdrSize + PyldLenSize + PackIdSize + n
		pack := make([]byte, packLen)
		binary.LittleEndian.PutUint16(pack[0:], Data)
		binary.LittleEndian.PutUint32(pack[2:], uint32(n))
		binary.LittleEndian.PutUint32(pack[6:], packID)
		copy(pack[10:], dat[0:n])
		pc.WriteTo(pack, addr)
		i += int64(n)
		packID++
	}
}

func handlePacketConnection(pc net.PacketConn) {
	reqCount := 0
	buff := make([]byte, 1010)
	for {
		count, clientAddr, err := pc.ReadFrom(buff)
		if err != nil {
			fmt.Println(err)
			return
		}
		recvd := buff[0:count]
		header := binary.LittleEndian.Uint16(buff[0:])

		switch header {
		case JoinReq:
			pc.WriteTo(passReqArr, clientAddr)
			reqCount++
		case PassResp:
			tPass := string(recvd[6:])
			if strings.Compare(tPass, clientPassword) == 0 {
				pc.WriteTo(passAccArr, clientAddr)
				// Password accepted, now send file
				sendFile(pc, clientAddr)
				// Terminate
				terminate(pc, clientAddr)
				return
			}

			if reqCount < 3 {
				pc.WriteTo(passReqArr, clientAddr)
				reqCount++
			} else {
				pc.WriteTo(rejectArr, clientAddr)
				fmt.Println("ABORT")
				return
			}
		default:
			fmt.Println("ABORT")
			return
		}
	}
}

func main() {
	args := os.Args
	if len(args) != 4 {
		usage()
		return
	}

	// Parse command line args
	mPort := args[1]
	clientPassword = args[2]
	inputFilePath = args[3]

	_, err := strconv.Atoi(mPort)
	if err != nil {
		usage()
		return
	}

	addr := ":" + mPort
	pc, err := net.ListenPacket("udp4", addr)
	defer pc.Close()
	checkError(err)

	handlePacketConnection(pc)
}
