# A very very simple VXLAN Hub

## What is this?

This is a very simple VXLAN learning switch (well, it used to be a hub when it only supported two connections, but now it learns MACs!) written in Go.

It uses simple UDP sockets to bind to a port that's suspiciously like VXLAN's (except it's that, plus 10000, to get around some clouds filtering VXLAN's port), receiving and sending VXLAN packets on it.
`gopacket` is used to parse and build VXLAN packets.

## How does it work?

The application simply listens on port 14789 for any incoming traffic. If it's a valid VXLAN packet, the VNI is checked -- this is the only form of authentication the application has, really.
At the moment, only a single VNI is supported, and if the VNI does not match the one set in the `VNI` environment variable, the packet is discarded.

If the VNI in the packet matches with the configured VNI, the processing of the VXLAN packet continues. If the source of the VXLAN packet is not yet known, that "remote VTEP" is learned.

Received VXLAN packets are decapsulated to the Ethernet frame payload level, where the source and destination MACs are inspected.
If the source MAC address is not a special MAC address (i.e. multicast, null or broadcast MAC), it is learned. In case the MAC was already learned and the source VTEP does not match the already learned VTEP, a MAC move is noted between the VTEPs and the new VTEP will be considered the destination VTEP for that MAC.

In case the received packet is a BUM (broadcast, multicast, or unknown unicast, where the destination MAC is not yet known) packet, the VXLAN hub floods all VTEPs (except where the packet ingressed from, aka split horizon) with the contents of the received packet.
All other unicast packets are directly sent to the remote VTEP where the destination MAC was learnt from.

Additionally, the VXLAN Hub will send keepalive packets periodically to each remote VTEP, in order to prevent NAT sessions from timing out, in case the remote VTEP is a quiet host.

## What is missing from it?

### VTEP aging

At the moment, remote VTEPs are once learned, and never forgotten.
This can lead to an accumulation of inactive/invalid remote VTEP destinations, in cases such as:

- long runtime
- VTEP sending traffic with random source ports
- VTEP impacted by (CG)-NAT or other forms of address translation, and source port is not persistently translated across a period of time

#### Proposed fix

Add timer for each learned VTEP, if no incoming traffic -> remove from list of VTEPs. A "last seen" timestamp should be kept up to date for each VTEP, updated at each incoming packet from said VTEP.

### MAC aging

MAC addresses are also not aged out. This can lead to issues where a single VTEP can permanently occupy memory by flooding the VXLAN Hub with random source MACs.

#### Proposed fix

Add a timer for each learned MAC, if MAC not seen for a set amount of time -> remove from list of MACs. A "last seen" timestamp should be kept up to date for each MAC, updated at each incoming packet based on the source MAC address.

### Multi-VNI (or dynamic VNI?) support

The code is modular, but does not spawn multiple VXLAN Hub instances. A list/range of allowed VNIs would be nice to have, to be able to segment hosts in groups within the VXLAN Hub.
There is some potential here for an interesting workshop idea, where two separate VNIs are connected.

Adding dynamic VNI support would remove a factor of authentication from the application, and would open the door for abuse (for there is no handshake required to learn a new VTEP, a single VXLAN packet with the correct VNI triggers this!)
