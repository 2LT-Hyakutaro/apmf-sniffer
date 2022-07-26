use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};
use etherparse::{InternetSlice, ReadError, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Active, Inactive};
use pcap::Error::TimeoutExpired;
use crate::Error::*;
use crate::Port::{Tcp, Udp, Unknown};
use crate::ports::{Port, TcpPort, UdpPort};
use crate::Status::{Sniffing, Initialized, Paused};

mod report;

#[cfg(test)]
mod tests {
    use crate::ports::TcpPort;

    #[test]
    fn test_tcp_port() {
        println!("{:?}", TcpPort::from(2));
    }
}

#[derive(Debug)]                // required for .unwrap()
pub enum Error {
    NoSuchDevice,
    IllegalAction,              /* returned when a method is called when in the wrong state (e.g. start() when already active) */
    RustPcapError(pcap::Error),
    FilterError(String),
    ParsingError(etherparse::ReadError),
    DisconnectedThread,
    InternalError,
    PacketNotRecognized
}

impl From<pcap::Error> for Error {
    fn from(e: pcap::Error) -> Self {
        if e.to_string().contains("can't parse filter expression") {
            FilterError(e.to_string().to_string())
        } else {
            RustPcapError(e)
        }
    }
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        ParsingError(e)
    }
}
#[derive(Debug, PartialEq)]
pub enum Status {
    Uninitialized,
    Initialized,
    Sniffing,
    Paused
}

#[derive(PartialEq, Eq)]
enum Command {
    Stop,
    Pause,
    Resume
}


pub struct APMFSniffer {
    pub device : Device,
    pub capture : Option<Capture<Active>>,
    pub status : Status,
    pub interval : u64,
    pub output : String,            // will need to be changed
    sender: Option<Sender<Command>>
}

impl APMFSniffer {

    fn new(device : Device, status : Status, interval : u64, output : String) -> Self {
        APMFSniffer{device, capture : None, status, interval, output, sender: None}
    }

    /// # Errors
    /// * `RustPcapError` if o capture cannot be activated on the device (e.g. because the interface is down)
    /// * `FilterError` if the BPF string provided was incorrect.
    pub fn start(&mut self, filter : &str) -> Result<(), Error> {

        let default_filter = "tcp or udp";
        let f = if filter == "" {default_filter} else {filter};
        if self.status != Initialized { return Err(IllegalAction); }

        let res_cap = Capture::from_device(self.device.name.as_str())?;
        let active_cap = self.activate_capture(res_cap, f)?;
        self.status = Sniffing;
        self.start_capture_thread(active_cap, self.interval);

        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), Error> {
        if self.status != Paused { return Err(IllegalAction); }
        if self.sender.is_none() {
            return Err(InternalError); // this should never happen!
        }
        let res = self.sender.as_ref().unwrap().send(Command::Resume);
        if res.is_err() {
            // TODO: decide what happens in this case, the receiver is disconnected,
            // should a new thread be started or should we return an error?
            return Err(DisconnectedThread);
        }


        Ok(())
    }


    pub fn pause(&mut self) -> Result<(), Error> {
        return if self.status == Sniffing {
            self.status = Paused;
            let res = self.sender.as_ref().unwrap().send(Command::Pause);
            if res.is_err() {
                return Err(Error::DisconnectedThread) // maybe change to not generic error depending on the error?
            }
            Ok(())
        } else {
            Err(IllegalAction)
        }
    }

    fn activate_capture(&self, cap: Capture<Inactive>, filter : &str) -> Result<Capture<Active>, Error> {
        let mut capture = cap.promisc(true)
            .immediate_mode(false)               // packets are picked up immediately (no buffering)
            .open()?
            .setnonblock()?;

        capture.filter(filter, false)?;

        Ok(capture)
    }

    fn start_capture_thread(&mut self, mut cap: Capture<Active>, interval : u64) {
        let (sender, receiver): (Sender<Command>, Receiver<Command>) = channel();
        self.sender = Some(sender);
        thread::spawn(move || {

            let mut last_report = Instant::now();
            let mut n = 0;


            // this should make the thread automatically stop if the sender disconnects

            loop {
                /* check timer */
                let now = Instant::now();
                if now - last_report > Duration::from_millis(interval) {
                    n += 1;
                    last_report = now;
                    // TODO: start a thread that produces the report
                    let stats = match cap.stats() {
                        Ok(s) => s,
                        _ => break,
                    };
                    println!("REPORT #{}: {:#?}", n, stats);
                }

                /* get packet */
                let packet = match cap.next() {
                    Ok(p) => p,
                    Err(TimeoutExpired) => continue,
                    _ => break,
                };

                /* parse packet */
                let apmf_packet = match parse_packet(packet) {
                    Ok(p) => p,
                    Err(PacketNotRecognized) => continue,
                    _ => break,
                };

                /* save packet */


                let res = receiver.try_recv();
                if res.is_err() {
                    if res.err().unwrap() == TryRecvError::Empty {
                        continue
                    }
                    return;
                }
                let mut command = res.unwrap();
                loop {
                    match command {
                        Command::Stop => return,
                        Command::Pause => {
                            command = receiver.recv().unwrap();
                        }
                        Command::Resume => break
                    }
                }

            }

            // TODO: what if we get here?
            // we could get here if
            println!("Capturing thread exited!!!");
        });
    }
}

impl Drop for APMFSniffer {
    fn drop(&mut self) {
        if self.sender.is_none() {
            return;
        }
        self.sender.as_ref().unwrap().send(Command::Stop).unwrap_or(());
        // It is fine to ignore the error, because in that
        // case the thread should already have been stopped
    }
}


/// Returns a new [`APMFSniffer`] that will listen in promiscuous mode on the interface `dev_name`;
/// only packets that match the BPF program string `bpf` are picked up.
/// `""` is a valid filter that matches all packets.
/// # Errors
/// * [`RustPcapError`] if [`Device::list()`] fails.
/// * [`NoSuchDevice`] if the provided name does not match any device name.
pub fn init(dev_name : &str, millis : u64) -> Result<APMFSniffer, Error> {

    let list = Device::list()?;        // can return MalformedError, PcapError, InvalidString

    for dev in list {
        if dev.name == dev_name {
            return Ok(APMFSniffer::new(dev, Initialized, millis, "stdout?".to_string()))
        }
    }

    Err(NoSuchDevice)
}

/// Returns a vector containing strings that describe devices available in the format `name: description`
/// # Errors
/// * [`RustPcapError`] if [`Device::list()`] fails.
pub fn list_devices() -> Result<Vec<String>, Error> {
    let list = Device::list()?;      // can return MalformedError, PcapError, InvalidString
    return Ok(list.into_iter().map(|d| format!("{}: {}", d.name, d.desc.unwrap_or("no description".to_string()))).collect());
}

fn parse_packet(p : pcap::Packet) -> Result<APMFPacket, Error> {

    let net_and_transport = SlicedPacket::from_ethernet(p.data)?;

    let transport_proto: &str;
    let app_proto : Port;
    let addresses;
    let ports;

    match net_and_transport.ip {
        Some(InternetSlice::Ipv4(ip, ..)) => {
            addresses = Some((IpAddr::from(ip.source_addr()), IpAddr::from(ip.destination_addr())));
        },
        Some(InternetSlice::Ipv6(ip, ..)) => {
            addresses = Some((IpAddr::from(ip.source_addr()), IpAddr::from(ip.destination_addr())));
        },
        _ => {
            addresses = None;
        }
    }

    match net_and_transport.transport {
        Some(TransportSlice::Udp(udp)) => {
            ports = Some((udp.source_port(), udp.destination_port()));
            transport_proto = "udp";
            app_proto = Udp(UdpPort::from(udp.source_port()))
        },
        Some(TransportSlice::Tcp(tcp)) => {
            ports = Some((tcp.source_port(), tcp.destination_port()));
            transport_proto = "tcp";
            app_proto = Tcp(TcpPort::from(tcp.source_port()));
        },
        _ => {
            ports = None;
            transport_proto = "unknown";
            app_proto = Unknown;
        }
    }

    return if addresses.is_some() && ports.is_some() {
        let a_packet = APMFPacket {
            src_addr : addresses.unwrap().0,
            dest_addr : addresses.unwrap().1,
            src_port : ports.unwrap().0,
            dest_port : ports.unwrap().1,
            timestamp: ((p.header.ts.tv_sec as u128) * 1000000000) + (p.header.ts.tv_usec as u128), // should mathematically be impossible to have overflow
            n_bytes: p.header.len,
            protocol: transport_proto,
            application : app_proto
        };

        println!("{:?}", a_packet);
        Ok(a_packet)
    } else {
     Err(PacketNotRecognized)
    }
}

#[derive(Debug)]
pub struct APMFPacket {
    src_addr: IpAddr,
    dest_addr: IpAddr,
    src_port: u16,
    dest_port: u16,
    timestamp: u128, // nanoseconds in unix epoch
    n_bytes: u32,
    protocol: &'static str,
    application: Port
}

mod ports {
    use crate::ports::TcpPort::*;

    #[derive(Debug)]
    pub enum Port {
        Tcp(TcpPort),
        Udp(UdpPort),
        Unknown
    }

    #[derive(Debug)]
    pub enum TcpPort {
        Echo,
        FTPData,
        FTPControl,
        SSH,
        DNS,
        Telnet,
        SMTP,
        POP2,
        POP3,
        IMAP,
        BGP,
        IRC,
        HTTPS,
        SMTPS,
        IKE,
        DHCPv6Client,
        DHCPv6Server,
        Doom,
        DNSOverTLS,
        ISCSI,
        FTPSData,
        FTPSControl,
        TelnetOverTLS,
        IMAPS,
        POP3S,
        UnknownProtocol
    }
    /*
     sed -E 's/\b(.)/\u\1/g' prova.txt | sed -E s/[[:blank:]]//g | sed  s/\\/Tcp/" => "/ | sed s/\\/Udp/" => "/
    */
    impl From<u16> for TcpPort {
        fn from(p: u16) -> Self {
            match p {
                7 => Echo,
                20 => FTPData,
                21 => FTPControl,
                22 => SSH,
                23 => Telnet,
                25 => SMTP,
                53 => DNS,
                109 => POP2,
                110 => POP3,
                143 => IMAP,
                179 => BGP,
                194 => IRC,
                220 => IMAP,
                443 => HTTPS,
                465 => SMTPS,
                500 => IKE,
                546 => DHCPv6Client,
                547 => DHCPv6Server,
                587 => SMTP,
                666 => Doom,
                853 => DNSOverTLS,
                860 => ISCSI,
                989 => FTPSData,
                990 => FTPSControl,
                992 => TelnetOverTLS,
                993 => IMAPS,
                995 => POP3S,
                _ => UnknownProtocol
            }
        }
    }

    #[derive(Debug)]
    pub enum UdpPort {
        Echo,
        DNS,
        DHCP,
        NTP,
        SNMP,
        IRC,
        IMAP,
        HTTPS,
        RIP,
        DHCPv6Client,
        DHCPv6Server,
        Doom,
        DNSOverQUIC,
        FTPSData,
        FTPSControl,
        TelnetOverTLS,
        POP3S,
        UnknownProtocol
    }

    impl From<u16> for UdpPort {
        fn from(p: u16) -> Self {
            match p {
                7 => UdpPort::Echo,
                53 => UdpPort::DNS,
                67 => UdpPort::DHCP,
                68 => UdpPort::DHCP,
                123 => UdpPort::NTP,
                161 => UdpPort::SNMP,
                194 => UdpPort::IRC,
                220 => UdpPort::IMAP,
                443 => UdpPort::HTTPS,
                520 => UdpPort::RIP,
                546 => UdpPort::DHCPv6Client,
                547 => UdpPort::DHCPv6Server,
                666 => UdpPort::Doom,
                853 => UdpPort::DNSOverQUIC,
                989 => UdpPort::FTPSData,
                990 => UdpPort::FTPSControl,
                992 => UdpPort::TelnetOverTLS,
                995 => UdpPort::POP3S,
                _ => UdpPort::UnknownProtocol
            }
        }
    }
}