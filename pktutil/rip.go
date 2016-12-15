package pktutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type ripPacketRaw struct {
	Command  uint8
	Version  uint8
	Reserved uint16
	Entries  []*ripEntriesRaw
	RipTime  time.Time
}

type ripEntriesRaw struct {
	Identifier uint16
	Tag        uint16
	Address    uint32
	Subnet     uint32
	Hop        uint32
	Metric     uint32
}

type RipPacket struct {
	RipTime    string `db:"RIP_Time"`
	SourceAddr string `db:"Source_IP"`
	Address    string `db:"RIP_IP"`
	Subnet     string `db:"RIP_Netmask"`
	NextHop    string `db:"RIP_Next_hop"`
	Metric     uint32 `db:"RIP_Metric"`
	TestId     int64  `db:"Test_Id"`
}

func ParseRip(pcapPath string, ripChan chan *RipPacket) {

	handle, err := pcap.OpenOffline(pcapPath)
	defer handle.Close()
	defer close(ripChan)

	if err != nil {
		fmt.Println("Open error", err)
		return
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
			} else if appLayer := readPacket.ApplicationLayer(); appLayer != nil {
				rip := parseRipPayload(appLayer.Payload())

				for _, entry := range rip.Entries {
					if entry == nil {
						continue
					}

					temp := make([]byte, 4)
					binary.BigEndian.PutUint32(temp, entry.Address)

					ripAddress := net.IP(temp).String()
					metric := entry.Metric

					binary.BigEndian.PutUint32(temp, entry.Subnet)
					subnet := net.IP(temp).String()

					binary.BigEndian.PutUint32(temp, entry.Hop)
					nextHop := net.IP(temp).String()

					//ripTime := strconv.FormatFloat((float64(rip.RipTime.UnixNano()) / 1000000000.0), 'f', -1, 64)
					ripTime := rip.RipTime.UTC().Format("2006-01-02 15:04:05.000000")

					newRip := &RipPacket{
						RipTime: ripTime,
						Address: ripAddress,
						Subnet:  subnet,
						NextHop: nextHop,
						Metric:  metric}

					ripChan <- newRip
				}
			}
		}
	}
}

func parseRipPayload(payload []byte) *ripPacketRaw {
	var command uint8
	var version uint8

	ripPacket := ripPacketRaw{}

	buf := bytes.NewBuffer(payload)

	err := binary.Read(buf, binary.BigEndian, &command)
	if err != nil {
		log.Println(err)
	}

	err = binary.Read(buf, binary.BigEndian, &version)
	if err != nil {
		log.Println(err)
	}

	// Skip the unused bytes in the payload
	buf.Next(2)

	// Each entry is 20 bytes in length
	numEntries := buf.Len() / 20
	ripPacket.Entries = make([]*ripEntriesRaw, numEntries)

	for i := 0; i < numEntries; i++ {
		entry := ripEntriesRaw{}

		err = binary.Read(buf, binary.BigEndian, &entry)
		if err != nil {
			log.Println(err)
		}

		ripPacket.Entries = append(ripPacket.Entries, &entry)
	}

	ripPacket.Version = version
	ripPacket.Command = command

	return &ripPacket
}
