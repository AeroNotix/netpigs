package procnet

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type ProcNet struct {
	LocalAddr, RemoteAddr           net.IP
	bytesLocalAddr, bytesRemoteAddr [16]byte
}
type Connections struct {
	sync.Mutex
	addrs map[string]string
}

func fromHexChar(c byte) uint8 {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func parseHex(s []byte) uint {
	n := uint(0)
	for i := 0; i < len(s); i++ {
		n *= 16
		n += uint(fromHexChar(s[i]))
	}
	return n
}

func scanAddressNA(in []byte, buf *[16]byte) net.IP {
	col := bytes.IndexByte(in, ':')
	if col == -1 {
		return nil
	}
	address := hexDecode32bigNA(in[:col], buf)
	return net.IP(address)
}

func hexDecode32bigNA(src []byte, buf *[16]byte) []byte {
	blocks := len(src) / 8
	for block := 0; block < blocks; block++ {
		for i := 0; i < 4; i++ {
			a := fromHexChar(src[block*8+i*2])
			b := fromHexChar(src[block*8+i*2+1])
			buf[block*4+3-i] = (a << 4) | b
		}
	}
	return buf[:blocks*4]
}

// Parse parses all the tcp (not tcp6) entries in /proc/*/net/ it is
// likely very inefficient, error prone, but it works for now until it
// needs to be optimized. Which it will need optimizing.
func (c Connections) Parse() {
	// TODO: fix the glob, it matches [0-9]ANYTHING
	paths, err := filepath.Glob("/proc/[0-9]*/net/tcp")
	if err != nil {
		panic(err)
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			for scanner.Scan() {
				proc := ProcNet{}
				wordscanner := bufio.NewScanner(bytes.NewReader(scanner.Bytes()))
				wordscanner.Split(bufio.ScanWords)
				wordscanner.Scan()
				wordscanner.Scan()
				localAddr := wordscanner.Bytes()
				wordscanner.Scan()
				remoteAddr := wordscanner.Bytes()
				proc.LocalAddr = scanAddressNA(localAddr, &proc.bytesLocalAddr)
				proc.RemoteAddr = scanAddressNA(remoteAddr, &proc.bytesRemoteAddr)
				fmt.Println(proc.LocalAddr, proc.RemoteAddr)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}
