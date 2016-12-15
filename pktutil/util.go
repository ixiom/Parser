package pktutil

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func ParsePcap(path string, packetChan chan *DataPacket, ripChan chan RipPacket) {

}

/* GetNodeFromRip
** Parses a PCAP until it finds the first RIP packet.
** If we are parsing an ultra pcap we can parse the filename
** and get the node ID. If we are parsing, for example, a NettWarrior data set,
** we will have to look for a RIP packet and assume the node ID is 1 higher than the
** RIP packet's source IP.
** 11/08/2016
** SPECIAL CASE: I am going to assume right now that if the IP is sourced from
** a 155.x.x.x IP than it is a Manpack and it does not have an EUD attached, and sending
** traffic. A cutsheet of IPs would be helpful.
 */
func GetNodeFromRip(pcapPath string) int {
	handle, err := pcap.OpenOffline(pcapPath)
	defer handle.Close()

	if err != nil {
		fmt.Println("Open error", err)
		return 0
	} else {
		err = handle.SetBPFFilter("dst host 224.0.0.9")
		if err != nil {
			panic(err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
			} else if netLayer := readPacket.NetworkLayer(); netLayer != nil {
				srcIpString := netLayer.NetworkFlow().Src().String()
				ipSplit := strings.Split(srcIpString, ".")
				nodeIdSplit := ipSplit[2]
				nodeId, _ := strconv.Atoi(nodeIdSplit)

				return nodeId
			}
		}
	}

	return 0
}

/* GetIgmp
**
 */
func GetIgmp(pcapPath string) string {
	handle, err := pcap.OpenOffline(pcapPath)
	defer handle.Close()

	if err != nil {
		fmt.Println("Open error", err)
		return ""
	} else {
		err = handle.SetBPFFilter("dst host 224.0.0.9")
		if err != nil {
			panic(err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
			} else if netLayer := readPacket.NetworkLayer(); netLayer != nil {
				srcIpString := netLayer.NetworkFlow().Src().String()

				return srcIpString
			}
		}
	}

	return ""
}

func GetPcapStartEnd(pcapFile string) (start, end time.Time) {
	handle, err := pcap.OpenOffline(pcapFile)
	defer handle.Close()

	if err != nil {
		fmt.Println("Open error", err)
		return start, end
	}

	for {
		_, ci, err := handle.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Println(err)
		} else if err == io.EOF {
			break
		} else {
			if start.IsZero() {
				start = ci.Timestamp
			}
			end = ci.Timestamp
		}
	}

	return start, end
}
