/**
* Homer Encapsulation Protocol v3
* Courtesy of Weave Communications, Inc (http://getweave.com/) under the ISC license (https://en.wikipedia.org/wiki/ISC_license)
**/

package hep

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/dgv/sipparser"
)

/*************************************
 Constants
*************************************/

// HEP ID
const (
	HEP_ID1 = 0x011002
	HEP_ID2 = 0x021002
	HEP_ID3 = 0x48455033
)

// Generic Chunk Types
const (
	_ = iota // Don't want to assign zero here, but want to implicitly repeat this expression after...
	IP_PROTOCOL_FAMILY
	IP_PROTOCOL_ID
	IP4_SOURCE_ADDRESS
	IP4_DESTINATION_ADDRESS
	IP6_SOURCE_ADDRESS
	IP6_DESTINATION_ADDRESS
	SOURCE_PORT
	DESTINATION_PORT
	TIMESTAMP
	TIMESTAMP_MICRO
	PROTOCOL_TYPE // Maps to Protocol Types below
	CAPTURE_AGENT_ID
	KEEP_ALIVE_TIMER
	AUTHENTICATE_KEY
	PACKET_PAYLOAD
	COMPRESSED_PAYLOAD
	INTERNAL_C
)

var ProtocolFamilies []string
var Vendors []string
var ProtocolTypes []string

func init() {

	// Protocol Family Types - HEP3 Spec does not list these values out. Took IPv4 from an example.
	ProtocolFamilies = []string{
		"?",
		"?",
		"IPv4"}

	// Initialize vendors
	Vendors = []string{
		"None",
		"FreeSWITCH",
		"Kamailio",
		"OpenSIPS",
		"Asterisk",
		"Homer",
		"SipXecs",
	}

	// Initialize protocol types
	ProtocolTypes = []string{
		"Reserved",
		"SIP",
		"XMPP",
		"SDP",
		"RTP",
		"RTCP",
		"MGCP",
		"MEGACO",
		"M2UA",
		"M3UA",
		"IAX",
		"H322",
		"H321",
	}
}

// Define Struct for storing full HEP message
type HepMsg struct {
	IpProtocolFamily      byte
	IpProtocolId          byte
	Ip4SourceAddress      string
	Ip4DestinationAddress string
	Ip6SourceAddress      string
	Ip6DestinationAddress string
	SourcePort            uint16
	DestinationPort       uint16
	Timestamp             uint32
	TimestampMicro        uint32
	ProtocolType          byte
	CaptureAgentId        uint16
	KeepAliveTimer        uint16
	AuthenticateKey       string
	Body                  string
	SipMsg                *sipparser.SipMsg
	//SipMsg	*sip.SipMsg
}

func NewHepMsg(packet []byte) (*HepMsg, error) {
	newHepMsg := &HepMsg{}
	err := newHepMsg.Parse(packet)
	if err != nil {
		return nil, err
	}
	return newHepMsg, nil
}

func (hepMsg *HepMsg) Parse(udpPacket []byte) error {

	switch udpPacket[0] {
	case 0x01:
		return hepMsg.ParseHep1(udpPacket)
	case 0x02:
		return hepMsg.ParseHep2(udpPacket)
	case 0x48:
		return hepMsg.ParseHep3(udpPacket)
	default:
		err := errors.New("Not a valid HEP packet - HEP ID does not match spec")
		return err
	}
}
func (hepMsg *HepMsg) ParseHep1(udpPacket []byte) error {
	//var err error
	if len(udpPacket) < 21 {
		return errors.New("Found HEP ID for HEP v1, but length of packet is too short to be HEP1 or is NAT keepalive")
	}
	packetLength := len(udpPacket)
	hepMsg.SourcePort = binary.BigEndian.Uint16(udpPacket[4:6])
	hepMsg.DestinationPort = binary.BigEndian.Uint16(udpPacket[6:8])
	hepMsg.Ip4SourceAddress = net.IP(udpPacket[8:12]).String()
	hepMsg.Ip4DestinationAddress = net.IP(udpPacket[12:16]).String()
	hepMsg.Body = string(udpPacket[16:])
	if len(udpPacket[16:packetLength-4]) > 1 {
		hepMsg.SipMsg = sipparser.ParseMsg(string(udpPacket[16:packetLength]))
		//hepMsg.SipMsg, err = sip.NewSipMsg(udpPacket[16 : packetLength-4])
		if hepMsg.SipMsg.Error != nil {
			return hepMsg.SipMsg.Error
		}
	} else {

	}

	return nil
}

func (hepMsg *HepMsg) ParseHep2(udpPacket []byte) error {
	//var err error
	if len(udpPacket) < 31 {
		return errors.New("Found HEP ID for HEP v2, but length of packet is too short to be HEP2 or is NAT keepalive")
	}
	packetLength := len(udpPacket)
	hepMsg.SourcePort = binary.BigEndian.Uint16(udpPacket[4:6])
	hepMsg.DestinationPort = binary.BigEndian.Uint16(udpPacket[6:8])
	hepMsg.Ip4SourceAddress = net.IP(udpPacket[8:12]).String()
	hepMsg.Ip4DestinationAddress = net.IP(udpPacket[12:16]).String()
	hepMsg.Timestamp = binary.LittleEndian.Uint32(udpPacket[16:20])
	hepMsg.TimestampMicro = binary.LittleEndian.Uint32(udpPacket[20:24])
	hepMsg.CaptureAgentId = binary.BigEndian.Uint16(udpPacket[24:26])
	hepMsg.Body = string(udpPacket[28:])
	if len(udpPacket[28:packetLength-4]) > 1 {
		hepMsg.SipMsg = sipparser.ParseMsg(string(udpPacket[28:packetLength]))
		//hepMsg.SipMsg, err = sip.NewSipMsg(udpPacket[16 : packetLength-4])
		if hepMsg.SipMsg.Error != nil {
			return hepMsg.SipMsg.Error
		}
	} else {

	}

	return nil
}

func (hepMsg *HepMsg) ParseHep3(udpPacket []byte) error {
	length := binary.BigEndian.Uint16(udpPacket[4:6])
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := udpPacket[currentByte:]
		//chunkVendorId := binary.BigEndian.Uint16(hepChunk[:2])
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case IP_PROTOCOL_FAMILY:
			hepMsg.IpProtocolFamily = chunkBody[0]
		case IP_PROTOCOL_ID:
			hepMsg.IpProtocolId = chunkBody[0]
		case IP4_SOURCE_ADDRESS:
			hepMsg.Ip4SourceAddress = net.IP(chunkBody).String()
		case IP4_DESTINATION_ADDRESS:
			hepMsg.Ip4DestinationAddress = net.IP(chunkBody).String()
		case IP6_SOURCE_ADDRESS:
			hepMsg.Ip6SourceAddress = net.IP(chunkBody).String()
		case IP6_DESTINATION_ADDRESS:
			hepMsg.Ip4DestinationAddress = net.IP(chunkBody).String()
		case SOURCE_PORT:
			hepMsg.SourcePort = binary.BigEndian.Uint16(chunkBody)
		case DESTINATION_PORT:
			hepMsg.DestinationPort = binary.BigEndian.Uint16(chunkBody)
		case TIMESTAMP:
			hepMsg.Timestamp = binary.BigEndian.Uint32(chunkBody)
		case TIMESTAMP_MICRO:
			hepMsg.TimestampMicro = binary.BigEndian.Uint32(chunkBody)
		case PROTOCOL_TYPE:
			hepMsg.ProtocolType = chunkBody[0]
		case CAPTURE_AGENT_ID:
			hepMsg.CaptureAgentId = binary.BigEndian.Uint16(chunkBody)
		case KEEP_ALIVE_TIMER:
			hepMsg.KeepAliveTimer = binary.BigEndian.Uint16(chunkBody)
		case AUTHENTICATE_KEY:
			hepMsg.AuthenticateKey = string(chunkBody)
		case PACKET_PAYLOAD:
			hepMsg.Body += string(chunkBody)
		case COMPRESSED_PAYLOAD:
		case INTERNAL_C:
		default:
		}
		currentByte += chunkLength
	}
	return nil
}
