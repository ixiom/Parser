package snmp

import "encoding/json"

type SnmpData struct {
	BatterInfo Battery `json:"battery"`
	GpsInfo    Gps     `json:"gps"`
	Channels   []Node  `json:"channels"`
}

type Battery struct {
	RespTime string `json:"respTime"`
	Life     string `json:"life"`
}

type Gps struct {
	RespTime  string `json:"respTime"`
	Latitude  string `json:"latitude"`
	Longitude string `json:"longitude"`
}

type Node struct {
	Node string     `json:"node"`
	Rssi Rssi       `json:"rssi"`
	Nbrs []Neighbos `json:"nbrs"`
}

type Rssi struct {
	RespTime string `json:"respTime"`
	Rssi     string `json:"rssi"`
}

type Neighbos struct {
	Hops   []Hop  `json:"hops"`
	Node   int    `json:"node"`
	Cost   int    `json:"cost"`
	Adj    string `json:"adj"`
	Island int    `json:"island"`
}

type Hop struct {
	Node string `json:"node"`
	Cost string `json:"cost"`
}

func GetBatteryInfo(jsonData string) *Battery {

	var snmpData SnmpData

	err := json.Unmarshal([]byte(jsonData), &snmpData)
	if err != nil {
		panic(err)
	}

	return &snmpData.BatterInfo
}

func GetGpsInfo(jsonData string) *Gps {
	var snmpData SnmpData

	err := json.Unmarshal([]byte(jsonData), &snmpData)
	if err != nil {
		panic(err)
	}

	return &snmpData.GpsInfo
}

func GetSnmpInfo(jsonData string) *SnmpData {
	var snmpData SnmpData

	err := json.Unmarshal([]byte(jsonData), &snmpData)
	if err != nil {
		panic(err)
	}

	return &snmpData
}
