package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Simple DNS traffic spy in Go
//
// $ sudo apt update && sudo apt install libpcap-dev
// $ go build main.go && sudo ./main
// * Filter:  udp and port 53
// A     api.openweathermap.org           127.0.0.53       192.241.167.16
//                                                         192.241.187.136
//                                                         192.241.245.161
// A     api.openweathermap.org           127.0.0.53       192.241.167.16
//                                                         192.241.187.136
//                                                         192.241.245.161
//

type dnsSpy struct {
	devName string
	devPort int
	err     error
	handle  *pcap.Handle
	srcIP   string
	dstIP   string
}

func newSpy() *dnsSpy {
	devName := os.Getenv("SPY_IFACE")
	if len(devName) == 0 {
		devName = "lo"
	}
	devPort := 53
	devPortStr := os.Getenv("SPY_PORT")
	if len(devPortStr) > 0 {
		newDevPort, err := strconv.Atoi(devPortStr)
		if err != nil {
			devPort = newDevPort
		}
	}

	return &dnsSpy{
		devName: devName,
		devPort: devPort,
	}
}

func (s *dnsSpy) handleDNS(dns layers.DNS) {
	for _, dnsQuestion := range dns.Questions {
		for i, a := range dns.Answers {
			var args []interface{}
			if i == 0 {
				args = []interface{}{dnsQuestion.Type.String(), string(dnsQuestion.Name), s.srcIP, a.String()}
			} else {
				args = []interface{}{"", "", "", a.String()}
			}
			log.Printf("%-5s %-32v %-16v %v\n", args...)
		}
	}
}

func (s *dnsSpy) handleIP4(ip4 layers.IPv4) {
	s.srcIP = ip4.SrcIP.String()
	s.dstIP = ip4.DstIP.String()
}

func (s *dnsSpy) handleIP6(ip6 layers.IPv6) {
	s.srcIP = ip6.SrcIP.String()
	s.dstIP = ip6.DstIP.String()
}

func (s *dnsSpy) openDevice() (err error) {
	filter := fmt.Sprintf("udp and port %d", s.devPort)

	log.Printf("interface=%v, bpf filter=%v", s.devName, filter)
	if s.handle, err = pcap.OpenLive(s.devName, 1600, false, pcap.BlockForever); err != nil {
		return
	}

	// set filter
	return s.handle.SetBPFFilter(filter)
}

func (s *dnsSpy) closeDevice() {
	if s.handle == nil {
		return
	}
	s.handle.Close()
	s.handle = nil
}

func (s *dnsSpy) capture() {
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		udp     layers.UDP
		dns     layers.DNS
		payload gopacket.Payload
	)

	log.Printf(strings.Repeat("-", 64))
	log.Printf("%-5s %-32v %-16v %v\n", "Type", "Query", "SrcIP", "Response")
	log.Printf("%-5s %-32v %-16v %v\n", strings.Repeat("-", 5), strings.Repeat("-", 32), strings.Repeat("-", 16), strings.Repeat("-", 8))

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		data, _, err := s.handle.ReadPacketData()
		if err != nil {
			log.Println("Error reading packet data: ", err)
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				s.handleIP4(ip4)
			case layers.LayerTypeIPv6:
				s.handleIP6(ip6)
			case layers.LayerTypeDNS:
				s.handleDNS(dns)
			}
		}

		if err != nil {
			log.Println("  Error encountered:", err)
		}
	}
}

func main() {
	log.SetFlags(0)
	spy := newSpy()

	err := spy.openDevice()
	if err != nil {
		log.Fatal(err)
	}
	defer spy.closeDevice()

	spy.capture()
}
