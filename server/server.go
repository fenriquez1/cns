package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	joinReq     uint16 = 1
	passReq     uint16 = 2
	passResp    uint16 = 3
	passAaccept uint16 = 4
	data        uint16 = 5
	terminate   uint16 = 6
	reject      uint16 = 7
	hdrSize     int    = 2
	pyldLenSize int    = 4
	packIDSize  int    = 4
)

var (
	clientPassword string
	inputFilePath  string
	aesgcm         cipher.AEAD
	nonce          []byte
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

func initCipherVariables() cipher.AEAD {
	// Create key from hash of password
	sum := sha256.Sum256([]byte(clientPassword))
	key := sum[0:]

	// Create cipher block
	block, err := aes.NewCipher(key)
	checkError(err)

	// Wrap cipher block in Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	checkError(err)

	return gcm
}

func terminateConnection(pc net.PacketConn, addr net.Addr) {
	// Get digest and send terminate packet
	data, err := ioutil.ReadFile(inputFilePath)
	checkError(err)
	digest := sha1.Sum(data)

	packLen := hdrSize + pyldLenSize + sha1.Size
	pack := make([]byte, packLen)
	binary.LittleEndian.PutUint16(pack[0:], terminate)
	binary.LittleEndian.PutUint32(pack[2:], uint32(len(digest)))
	copy(pack[6:], digest[0:])
	pc.WriteTo(encrypt(pack), addr)
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
		packLen := hdrSize + pyldLenSize + packIDSize + n
		pack := make([]byte, packLen)
		binary.LittleEndian.PutUint16(pack[0:], data)
		binary.LittleEndian.PutUint32(pack[2:], uint32(n))
		binary.LittleEndian.PutUint32(pack[6:], packID)
		copy(pack[10:], dat[0:n])
		pc.WriteTo(encrypt(pack), addr)
		i += int64(n)
		packID++
	}
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

func handlePacketConnection(pc net.PacketConn, addr net.Addr) bool {
	// Send PASS_REQ to addr who sent JOIN_REQ
	pc.WriteTo(encrypt(passReqArr), addr)

	reqCount := 0
	buff := make([]byte, 1010)
	for {
		count, clientAddr, err := pc.ReadFrom(buff)
		checkError(err)

		pt := decrypt(buff[0:count])
		header := binary.LittleEndian.Uint16(pt[0:])

		switch header {
		case passResp:
			tPass := string(pt[6:])
			if strings.Compare(tPass, clientPassword) == 0 {
				pc.WriteTo(encrypt(passAccArr), clientAddr)
				// Password accepted, now send file
				sendFile(pc, clientAddr)
				// terminate
				terminateConnection(pc, clientAddr)
				return true
			}

			if reqCount < 3 {
				pc.WriteTo(encrypt(passReqArr), clientAddr)
				reqCount++
			} else {
				pc.WriteTo(rejectArr, clientAddr)
				return false
			}
		default:
			return false
		}
	}
}

func listenForJoins(pc net.PacketConn) bool {
	for {
		buff := make([]byte, 1010)
		n, addr, err := pc.ReadFrom(buff)
		checkError(err)

		header := binary.LittleEndian.Uint16(buff[0:])
		if header == joinReq {
			pyldLen := binary.LittleEndian.Uint32(buff[2:])
			nonce = buff[6:n]
			if int(pyldLen) != len(nonce) {
				return false
			}
			return handlePacketConnection(pc, addr)
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

	aesgcm = initCipherVariables()

	if listenForJoins(pc) == true {
		fmt.Println("OK")
	} else {
		fmt.Println("ABORT")
	}

}
