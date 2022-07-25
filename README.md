# APMF sniffer
## Intended usage
APMF sniffer is a library that uses the rust libpcap library to capture packets on Windows, Linux and macOS.\
The library allows the user to capture packet on a user specified network adapter
by setting it in promiscuous mode, and generates reports on the traffic observed after
a specified time interval.\
The report is organized by source and destination port and address, and shows information
about the number of bytes exchanged, the transport and application (the application layer information
is not fully trustworthy as it uses the port to imply it), and a time of first and last
packet exchange.
## Installing pcap on your platform
The information for installing pcap is available on the rust libpcap github (https://github.com/rust-pcap/pcap).
For Windows the library suggested is no longer maintained, so you should install Npcap
instead, together with the Npcap SDK, and add the sdk to your environment variables

## Caveats
* This library assumes that your WLAN interface/driver transaltes 802.11 data pacjets to "fake" Ethernet packets
* In order to give *some* information about the application protocol contained in the packets, this library uses the simplest (and least accurate) identification method: port-based identification. This is also limited to just *some* of the 1024 well know ports.