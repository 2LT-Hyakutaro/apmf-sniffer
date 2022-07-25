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
