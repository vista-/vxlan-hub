package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	VXLANPort = 14789
)

type VXLANHub struct {
	VNI             uint32
	LocalVTEP       *net.UDPConn
	RemoteVTEPs     map[string]*net.UDPAddr
	MACs            map[string]*net.UDPAddr
	vtepMutex       sync.RWMutex
	macMutex        sync.RWMutex
	keepAlivePacket []byte
}

func NewVXLANHub(vni uint32) (*VXLANHub, error) {
	addr := net.UDPAddr{
		Port: VXLANPort,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, fmt.Errorf("could not open VXLAN UDP socket: %w", err)
	}

	keepAlivePacket, err := createKeepAlivePacket(vni)
	if err != nil {
		return nil, fmt.Errorf("could not create keepalive packet: %w", err)
	}

	hub := &VXLANHub{
		VNI:             vni,
		LocalVTEP:       conn,
		RemoteVTEPs:     make(map[string]*net.UDPAddr),
		MACs:            make(map[string]*net.UDPAddr),
		keepAlivePacket: keepAlivePacket,
	}

	return hub, nil
}

func (v *VXLANHub) vxlanDecap(packetBuf []byte) ([]byte, []byte, error) {
	// Is it a VXLAN packet?
	packet := gopacket.NewPacket(packetBuf, layers.LayerTypeVXLAN, gopacket.Default)
	vxlanLayer := packet.Layer(layers.LayerTypeVXLAN)
	if vxlanLayer == nil {
		return nil, nil, fmt.Errorf("not a valid VXLAN packet")
	}

	vxlanData := vxlanLayer.(*layers.VXLAN)
	if vxlanData.VNI != v.VNI {
		return nil, nil, fmt.Errorf("incorrect VNI in VXLAN packet")
	}

	return vxlanData.Contents, vxlanData.Payload, nil
}

func createKeepAlivePacket(vni uint32) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x00},
		EthernetType: 0x88CC,
	}

	ethBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	err := gopacket.SerializeLayers(ethBuf, opts, eth)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Ethernet frame: %v", err)
	}

	vxlan := &layers.VXLAN{
		ValidIDFlag: true,
		VNI:         vni,
	}

	vxlanBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(vxlanBuf, opts,
		vxlan,
		gopacket.Payload(ethBuf.Bytes()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VXLAN packet: %v", err)
	}

	log.Debugf("Created keepalive packet: %+v (%+v)", vxlan, eth)

	// Store keepalive packet on heap
	rawBytes := vxlanBuf.Bytes()
	vxlanPkt := make([]byte, len(rawBytes))
	copy(vxlanPkt, rawBytes)

	return vxlanPkt, nil
}

func (v *VXLANHub) sendKeepAlives(vtep *net.UDPAddr) {
	log.Debugf("Setting up session keepalive for VTEP %v", vtep)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Debugf("Sending keepalive to VTEP %v", vtep)
		_, err := v.LocalVTEP.WriteToUDP(v.keepAlivePacket, vtep)
		if err != nil {
			log.Errorf("Failed to send keepalive packet to VTEP %v: %v", vtep, err)
		}
	}
}

func (v *VXLANHub) learnVTEP(vtep *net.UDPAddr) {
	v.vtepMutex.Lock()
	defer v.vtepMutex.Unlock()

	vtepKey := vtep.String()
	if _, found := v.RemoteVTEPs[vtepKey]; !found {
		log.Infof("New remote VTEP learned: %v", vtepKey)
		v.RemoteVTEPs[vtep.String()] = vtep
		go v.sendKeepAlives(vtep)
	}
}

func (v *VXLANHub) extractMACs(payloadBuf []byte) (net.HardwareAddr, net.HardwareAddr, error) {
	packet := gopacket.NewPacket(payloadBuf, layers.LayerTypeEthernet, gopacket.Default)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, nil, fmt.Errorf("could not parse VXLAN Payload Ethernet header")
	}

	ethernetData := ethernetLayer.(*layers.Ethernet)
	dstMAC := ethernetData.DstMAC
	srcMAC := ethernetData.SrcMAC

	return dstMAC, srcMAC, nil
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	return mac.String() == "ff:ff:ff:ff:ff:ff"
}

func isMulticastMAC(mac net.HardwareAddr) bool {
	// First octet's least significant digit is 1
	return mac[0]&0x1 == 0x1
}

func isNullMAC(mac net.HardwareAddr) bool {
	return mac.String() == "00:00:00:00:00:00"
}

func (v *VXLANHub) learnMAC(mac net.HardwareAddr, vtep *net.UDPAddr) {
	if isBroadcastMAC(mac) {
		log.Debugf("Broadcast MAC received from %v, not learning: %v", vtep, mac)
		return
	}
	if isMulticastMAC(mac) {
		log.Debugf("Multicast MAC received from %v, not learning: %v", vtep, mac)
		return
	}
	if isNullMAC(mac) {
		log.Debugf("Null MAC received from %v, not learning: %v", vtep, mac)
		return
	}
	v.macMutex.Lock()
	defer v.macMutex.Unlock()

	learnedVTEP, found := v.MACs[mac.String()]
	if !found {
		v.MACs[mac.String()] = vtep
		log.Infof("Learning MAC for VTEP %v: %v", vtep, mac)
	}
	if vtep != learnedVTEP {
		v.MACs[mac.String()] = vtep
		log.Infof("MAC moved from VTEP %v to VTEP %v: %v", learnedVTEP, vtep, mac)
	}
}

func (v *VXLANHub) ingressReplicate(srcVTEP *net.UDPAddr) []*net.UDPAddr {
	v.vtepMutex.RLock()
	defer v.vtepMutex.RUnlock()

	var vteps []*net.UDPAddr
	for _, vtep := range v.RemoteVTEPs {
		// Split horizon
		if vtep.String() != srcVTEP.String() {
			vteps = append(vteps, vtep)
		}
	}

	if len(vteps) == 0 {
		log.Warnf("Cannot broadcast packet from %v: no other VTEPs are connected", srcVTEP)
	}

	return vteps
}

func (v *VXLANHub) lookupMAC(mac net.HardwareAddr) *net.UDPAddr {
	v.macMutex.RLock()
	defer v.macMutex.RUnlock()

	if dstVTEP, found := v.MACs[mac.String()]; found {
		return dstVTEP
	}

	return nil
}

func (v *VXLANHub) lookupDestination(dstMAC net.HardwareAddr, srcVTEP *net.UDPAddr) ([]*net.UDPAddr, error) {
	if isBroadcastMAC(dstMAC) {
		log.Debugf("Broadcast MAC destination, packet from %v will be replicated to all remote VTEPs", srcVTEP)
		return v.ingressReplicate(srcVTEP), nil
	}
	if isMulticastMAC(dstMAC) {
		log.Debugf("Multicast MAC destination, packet from %v will be replicated to all remote VTEPs", srcVTEP)
		return v.ingressReplicate(srcVTEP), nil
	}
	if isNullMAC(dstMAC) {
		return nil, fmt.Errorf("packet with null destination MAC address will not be forwarded")
	}

	dstVTEP := v.lookupMAC(dstMAC)
	// Unknown unicast case
	if dstVTEP == nil {
		return v.ingressReplicate(srcVTEP), nil
	}

	return []*net.UDPAddr{dstVTEP}, nil
}

func (v *VXLANHub) forward(vxlanPacket []byte, dstVTEPs []*net.UDPAddr) {
	for _, vtep := range dstVTEPs {
		_, err := v.LocalVTEP.WriteToUDP(vxlanPacket, vtep)
		if err != nil {
			log.Errorf("Failed to forward packet to %v: %v", vtep.String(), err)
		}
	}
}

func (v *VXLANHub) processPacket(packetBuf []byte, srcVTEP *net.UDPAddr) {
	vxlanHeader, vxlanPayload, err := v.vxlanDecap(packetBuf)
	if err != nil {
		log.Warnf("Received UDP packet could not be VXLAN decapsulated: %v", err)
		return
	}

	v.learnVTEP(srcVTEP)

	dstMAC, srcMAC, err := v.extractMACs(vxlanPayload)
	if err != nil {
		log.Errorf("Could not parse MAC addresses in VXLAN payload: %v", err)
		return
	}
	v.learnMAC(srcMAC, srcVTEP)

	dstVTEPs, err := v.lookupDestination(dstMAC, srcVTEP)
	if err != nil || len(dstVTEPs) == 0 {
		log.Warnf("Could not lookup destination (or no VTEPs): %v", err)
		return
	}

	v.forward(append(vxlanHeader, vxlanPayload...), dstVTEPs)
}

func (v *VXLANHub) Serve() {
	log.Infof("VXLAN Hub running on port %d with VNI %d", VXLANPort, v.VNI)

	buffer := make([]byte, 65535)

	for {
		n, addr, err := v.LocalVTEP.ReadFromUDP(buffer)
		if err != nil {
			log.Errorf("Failed to read from UDP socket: %v", err)
			continue
		}

		go v.processPacket(buffer[:n], addr)
	}

}

func (v *VXLANHub) Close() {
	v.LocalVTEP.Close()
}

func main() {
	vni_env := os.Getenv("VNI")
	log.SetLevel(log.DebugLevel)

	vni64, err := strconv.ParseUint(vni_env, 10, 24)
	if err != nil {
		log.Fatalf("Could not parse VNI: %v", err)
	}

	vni := uint32(vni64)

	// If VNI is larger than 24 bits, or smaller than 1, it's no good
	if vni <= 0 || vni > 0xFFFFFF {
		log.Fatalf("Parsed VNI %d is not in the valid range of 1-16777214", vni)
	}

	vxlanHub, err := NewVXLANHub(vni)
	if err != nil {
		log.Fatalf("Could not initialise VXLAN Hub: %v", err)
	}
	defer vxlanHub.Close()

	vxlanHub.Serve()
}
