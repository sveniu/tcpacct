package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Tally struct {
	SrcIP   net.IP
	DstIP   net.IP
	Packets uint64
	Bytes   uint64
}

func main() {
	termCh := make(chan struct{})
	go func(termCh chan<- struct{}) {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		close(termCh)
	}(termCh)

	// A map of flows to Tally struct pointers.
	flows := make(map[gopacket.Flow]*Tally)

	// The first arg is the capture device.
	handle, err := pcap.OpenLive(os.Args[1], 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Set default BPF filter to "ip" (IPv4), but override with command args.
	bpfFilter := "ip"
	if len(os.Args) > 2 {
		bpfFilter = strings.Join(os.Args[2:], " ")
	}
	log.Printf("BPF filter: %s", bpfFilter)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	}

	// Set up the packet source and channel.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := packetSource.Packets()

OuterLoop:
	for {
		select {

		case <-termCh:
			log.Print("exiting due to termination signal")
			break OuterLoop

		case packet := <-packetCh:
			ip4Layer := packet.NetworkLayer()
			if ip4Layer == nil {
				break
			}
			if ip4Layer.LayerType() != layers.LayerTypeIPv4 {
				break
			}
			ip4Packet := ip4Layer.(*layers.IPv4)

			nFlow := ip4Layer.NetworkFlow()

			if v, found := flows[nFlow]; found {
				v.Packets++
				v.Bytes += uint64(ip4Packet.Length)
			} else {
				flows[nFlow] = &Tally{
					SrcIP:   ip4Packet.SrcIP,
					DstIP:   ip4Packet.DstIP,
					Packets: 1,
					Bytes:   uint64(ip4Packet.Length),
				}
			}
		}
	}

	// Totals for packet and byte counters.
	totalPackets := uint64(0)
	totalBytes := uint64(0)

	fmt.Printf("src_ip\tdst_ip\tpackets\tbytes\n")
	for _, flow := range flows {
		fmt.Printf(
			"%s\t%s\t%d\t%d\n",
			flow.SrcIP.String(),
			flow.DstIP.String(),
			flow.Packets,
			flow.Bytes,
		)
		totalPackets += flow.Packets
		totalBytes += flow.Bytes
	}

	// Print the totals as well.
	fmt.Printf(
		"%s\t%s\t%d\t%d\n",
		"0.0.0.0",
		"0.0.0.0",
		totalPackets,
		totalBytes,
	)
}
