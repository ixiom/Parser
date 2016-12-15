package pktutil

import (
	"fmt"
	"io"

	"crypto/md5"
	"encoding/binary"
	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DataPacket struct {
	SourceIp string         `db:"Source_IP"`
	DestIp   string         `db:"Destination_IP"`
	DestPort layers.UDPPort `db:"Destination_Port"`
	Id       uint16         `db:"Packet_Id"`
	Length   int            `db:"Frame_Length"`
	Time     string         `db:"Time"`
	TestId   int64          `db:"Test_Id"`
	NodeId   int            `db:"Node_Id"`
	FileName string         `db:"FileName"`
	Tx       bool           `db:"TX"`
	Hash     string         `db:"Hash"`
}

func ParseDataPackets(pcapPath string, packetChan chan *DataPacket) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var udp layers.UDP
	var payload gopacket.Payload

	handle, err := pcap.OpenOffline(pcapPath)
	defer handle.Close()
	defer close(packetChan)

	if err != nil {
		fmt.Println("Open error", err)
		return
	} else {
		err = handle.SetBPFFilter("not dst host 224.0.0.9 and udp and not host 192.168.240.10")
		if err != nil {
			panic(err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &udp, &payload)
		decoded := []gopacket.LayerType{}

		for {
			readPacket, err := packetSource.NextPacket()

			if err == io.EOF {
				break
			} else if err != nil {
				if errNum, ok := err.(pcap.NextError); ok {
					if errNum == pcap.NextErrorReadError {
						continue
					} else {
						fmt.Println("Err ", errNum)
						panic(err)
					}
				}
			} else {
				parser.DecodeLayers(readPacket.Data(), &decoded)

				packetData := DataPacket{}

				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeIPv4:
						packetData.SourceIp = ip4.SrcIP.String()
						packetData.DestIp = ip4.DstIP.String()
						packetData.Id = ip4.Id
						packetData.Length = readPacket.Metadata().CaptureLength
						packetData.Time = readPacket.Metadata().Timestamp.UTC().Format("2006-01-02 15:04:05.000000")

					case layers.LayerTypeUDP:
						packetData.DestPort = udp.DstPort

					case gopacket.LayerTypePayload:
						// We have decoded to the payload layer. This
						// means the other layers have been successfully
						// decoded. We can now build the packet hash.
						hash := getPacketHash(&ip4, payload.Payload())
						packetData.Hash = hash
					}
				}

				packetChan <- &packetData
			}
		}
	}
}

func getPacketHash(ipv4Layer *layers.IPv4, payload []byte) string {

	/*fmt.Printf("Ver:         %d\n", ipv4Layer.Version)
	fmt.Printf("IHL:         %d\n", ipv4Layer.IHL)
	fmt.Printf("Length:      %d\n", ipv4Layer.Length)
	fmt.Printf("ID:          %d\n", ipv4Layer.Id)
	fmt.Printf("Flags:       %v\n", ipv4Layer.Flags)
	fmt.Printf("Frag offset: %d\n", ipv4Layer.FragOffset)
	fmt.Printf("Protocol:    %d\n", ipv4Layer.Protocol)
	fmt.Printf("Source IP:   %v\n", ipv4Layer.SrcIP)
	fmt.Printf("Dest IP:     %v\n", ipv4Layer.DstIP)*/

	bs := make([]byte, 16)
	var flagFrag uint16

	bs[0] = ipv4Layer.Version
	bs[0] = (bs[0] << 4) | ipv4Layer.IHL
	binary.LittleEndian.PutUint16(bs[1:], ipv4Layer.Length)
	binary.LittleEndian.PutUint16(bs[3:], ipv4Layer.Id)

	flagFrag = uint16(ipv4Layer.Flags)
	flagFrag = (flagFrag << 13) | ipv4Layer.FragOffset
	binary.LittleEndian.PutUint16(bs[5:], flagFrag)

	bs[7] = uint8(ipv4Layer.Protocol)
	srcByte := ipv4Layer.SrcIP.To4()
	bs[8] = srcByte[3]
	bs[9] = srcByte[2]
	bs[10] = srcByte[1]
	bs[11] = srcByte[0]

	srcByte = ipv4Layer.DstIP.To4()
	bs[12] = srcByte[3]
	bs[13] = srcByte[2]
	bs[14] = srcByte[1]
	bs[15] = srcByte[0]

	//payload := (*packet).ApplicationLayer().Payload()

	bs = append(bs[:], payload[:]...)

	h := md5.New()
	h.Write(bs)

	return hex.EncodeToString(h.Sum(nil))

	/*hexString := hex.EncodeToString(h.Sum(bs))

	if strings.Compare("45f800e67e0040110a09a8c0320c00efd41d8cd98f00b204e9800998ecf8427e", hexString) == 0 {
		fmt.Println("Found packet", fileName)
	}*/

	return ""
}
