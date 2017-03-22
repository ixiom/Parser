package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"stash.di2e.net/scm/ultra/reduction/snmp"

	"time"

	"log"

	flag "github.com/spf13/pflag"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"stash.di2e.net/scm/ultra/reduction/pktutil"
)

var (
	dbConn           = &sqlx.DB{}
	testId     int64 = 0
	wg         sync.WaitGroup
	err        error
	totalFiles = 0
	doneChan   chan bool
)

func snmpWorkerPool(snmpFiles chan string) {
	for snmpFile := range snmpFiles {
		wg.Add(1)
		parseSnmpFile(snmpFile)
	}
}

func packetWorkerPool(pcapFiles chan string) {
	for pcapFile := range pcapFiles {
		wg.Add(1)
		parsePcapFile(pcapFile)
	}
}

/*
** parsePcapFile
**
** Maybe there should be one util function that runs through
** the packet once and returns RIP, and data packets back on
** channels. For now we'll do it synchronously.
 */
func parsePcapFile(path string) {
	nodeInfo := `INSERT INTO ultratest.tbl_node_status (Test_Id, Node_Id, Start_Time, End_Time, IGMP_IP) VALUES (?, ?, ?, ?, ?)`
	ripInfo := "INSERT INTO ultratest.tbl_rip (Test_Id, Source_IP, RIP_IP, RIP_Metric, RIP_Netmask, RIP_Next_hop, RIP_Time) " +
		"VALUES (:Test_Id, :Source_IP, :RIP_IP, :RIP_Metric, :RIP_Netmask, :RIP_Next_hop, :RIP_Time)"

	pcapInfo := "INSERT INTO ultratest.tbl_packet_cap_test (Test_Id, Node_Id, FileName, " +
		"Source_IP, Destination_IP, " +
		"Destination_Port, Time, Frame_Length, " +
		"Packet_Id, TX, Hash) VALUES (:Test_Id, :Node_Id, :FileName, :Source_IP, :Destination_IP, :Destination_Port, " +
		":Time, :Frame_Length, :Packet_Id, :TX, :Hash)"

	fileSplit := strings.Split(filepath.Base(path), "-")

	defer wg.Done()

	//Assume file name is ultrax-.pcap
	node := strings.Split(fileSplit[0], "ultra")
	nodeId, _ := strconv.Atoi(node[1])

	srcIp := fmt.Sprintf("192.168.%d.10", nodeId)

	igmpIp := pktutil.GetIgmp(path)
	startTime, endTime := pktutil.GetPcapStartEnd(path)

	dbConn.MustExec(nodeInfo, testId, nodeId, startTime.UTC().Unix(), endTime.UTC().Unix(), igmpIp)

	ripChan := make(chan *pktutil.RipPacket)
	packetChan := make(chan *pktutil.DataPacket)

	go pktutil.ParseDataPackets(path, packetChan)
	go pktutil.ParseRip(path, ripChan)

	tx, _ := dbConn.Beginx()

	for openChans := 2; openChans > 0; {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				openChans--
				packetChan = nil
				break
			}

			packet.TestId = testId
			packet.NodeId = nodeId
			packet.FileName = filepath.Base(path)

			if strings.Compare(packet.SourceIp, srcIp) == 0 {
				packet.Tx = true
			} else {
				packet.Tx = false
			}

			_, err := tx.NamedExec(pcapInfo, packet)
			//_, err := stmtData.Exec(packet)
			if err != nil {
				log.Println(err)
			}

		case ripPacket, ok := <-ripChan:
			if !ok {
				openChans--
				ripChan = nil
				break
			}

			ripPacket.TestId = testId
			ripPacket.SourceAddr = igmpIp
			//stmt.Exec(ripPacket)
			_, err := tx.NamedExec(ripInfo, ripPacket)
			if err != nil {
				log.Println(err)
			}
		}
	}

	tx.Commit()
	doneChan <- true
}

func parseSnmpFile(path string) {
	fileSplit := strings.Split(filepath.Base(path), "_")

	defer wg.Done()

	//Assume file name is ultrax_HMS_SNMP.json
	node := strings.Split(fileSplit[0], "ultra")
	nodeId, _ := strconv.Atoi(node[1])

	readFile, _ := os.Open(path)

	scanner := bufio.NewScanner(readFile)

	transaction, err := dbConn.Beginx()
	if err != nil {
		panic(err)
	}

	for scanner.Scan() {
		snmpInfo := snmp.GetSnmpInfo(scanner.Text())

		for _, channel := range snmpInfo.Channels {
			channelEpoch, _ := time.Parse("2006-01-02 15:04:05.000000", channel.Rssi.RespTime)

			for _, nbr := range channel.Nbrs {

				if len(nbr.Hops) > 0 {
					for _, hop := range nbr.Hops {

						_, err = transaction.Exec("INSERT INTO tbl_forward (Test_Id, Req_Time, Resp_Time, Node_Id, Fwd_Node, Fwd_Hop, "+
							"Fwd_Cost) VALUES(?, 0, ?, ?, ?, ?, ?)",
							testId,
							channelEpoch.Unix(),
							channel.Node,
							hop.Node,
							nbr.Node,
							hop.Cost)

						if err != nil {
							panic(err)
						}
					}
				}

				_, err := transaction.Exec("INSERT INTO tbl_neighbor (Test_Id, Req_Time, Resp_Time, Node_Id, Island, Adjacency, Cost, Nbr_Node) "+
					"VALUES(?, 0, ?, ?, ?, ?, ?, ?)",
					testId,
					channelEpoch.Unix(),
					channel.Node,
					nbr.Island,
					nbr.Adj,
					nbr.Cost,
					nbr.Node)

				if err != nil {
					fmt.Println(err)
				}
			}
		}

		_, err := transaction.Exec("INSERT INTO ultratest.tbl_battery(Test_Id, Req_Time, Resp_Time, Batt_Level, Node_Id) VALUES(?, 0, ?, ?, ?)",
			testId,
			snmpInfo.BatterInfo.RespTime,
			snmpInfo.BatterInfo.Life,
			nodeId)

		if err != nil {
			fmt.Println(err)
		}

		gpsEpoch, _ := time.Parse("2006-01-02 15:04:05.000000", snmpInfo.GpsInfo.RespTime)

		_, err = transaction.Exec("INSERT INTO ultratest.tbl_positioninfo(Test_Id, Resp_Time, Node_Id, Latitude, Longitude) "+
			"VALUES(?, ?, ?, ?, ?)",
			testId,
			gpsEpoch.Unix(),
			nodeId,
			snmpInfo.GpsInfo.Latitude,
			snmpInfo.GpsInfo.Longitude)

		if err != nil {
			fmt.Println(err)
		}
	}

	err = transaction.Commit()
	if err != nil {
		panic(err)
	}

	readFile.Close()
	doneChan <- true
}

func main() {
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	dataDir := flag.StringP("dir", "d", "", "Data directory to look for testname")
	flag.Parse()

	doneChan = make(chan bool)
	snmpFileChan := make(chan string)
	pcapFileChan := make(chan string)

	if len(os.Args) != 2 && len(os.Args) != 4 {
		fmt.Println("Please enter test name on command line")
		return
	}

	var testName string

	if len(os.Args) == 2 {
		testName = os.Args[1]
	} else if len(os.Args) == 4 {
		testName = os.Args[3]
	}

	var snmpDir string
	if len(*dataDir) > 0 {
		snmpDir = fmt.Sprintf("%s/%s/*.json", *dataDir, testName)
	} else {
		snmpDir = fmt.Sprintf("/home/ultra/data/*/*/*/%s/*.json", testName)
	}

	// Find all SNMP files. They should be JSON files
	snmpMatches, err := filepath.Glob(snmpDir)
	if err != nil {
		fmt.Println("No SNMP matches")
	}

	var pcapDir string
	if len(*dataDir) > 0 {
		pcapDir = fmt.Sprintf("%s/%s/*.pcap", *dataDir, testName)
	} else {
		pcapDir = fmt.Sprintf("/home/ultra/data/*/*/*/%s/*.pcap", testName)
	}

	// Find all PCAP files.
	pcapMatches, err := filepath.Glob(pcapDir)
	if err != nil {
		fmt.Println("No PCAP matches")
	}

	totalFiles += len(pcapMatches) + len(snmpMatches)

	fmt.Printf("Total files: %3d\n", totalFiles)

	if totalFiles == 0 {
		fmt.Println("No files found for parsing")
		return
	}

	// Start Database connection
	dbConn, err = sqlx.Open("mysql", "root:ultra@tcp(172.17.0.2:3306)/ultratest")
	if err != nil {
		panic(err)
	}

	dbConn.SetMaxOpenConns(2000)
	dbConn.SetMaxIdleConns(2000)

	res, err := dbConn.Exec("INSERT INTO tbl_testcase(Description, Date) VALUES (?, ?)", testName, time.Now().Format(time.RFC3339))
	testId, _ = res.LastInsertId()

	// Start worker pool for parsing SNMP and PCAP files
	for i := 0; i < 5; i++ {
		go snmpWorkerPool(snmpFileChan)
	}

	for i := 0; i < 25; i++ {
		go packetWorkerPool(pcapFileChan)
	}

	// Send SNMP files for parsing
	wg.Add(1)
	go func() {
		for _, snmpMatch := range snmpMatches {
			snmpFileChan <- snmpMatch
		}

		for i := 0; i < 5; i++ {
			go packetWorkerPool(pcapFileChan)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for _, pcapMatch := range pcapMatches {
			pcapFileChan <- pcapMatch
		}
		wg.Done()
	}()

	for <-doneChan {
		totalFiles--
		fmt.Printf("\rFile remaining: %3d", totalFiles)
		if totalFiles == 0 {
			fmt.Println()
			break
		}
	}

	wg.Wait()

	err = dbConn.Close()
	if err != nil {
		log.Println(err)
	}
}
