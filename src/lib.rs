use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use etherparse::{InternetSlice, ReadError, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Active, Inactive};
use crate::Error::*;
use crate::Status::{Sniffing, Initialized, Paused};

#[cfg(test)]
mod tests {

}

#[derive(Debug)]                // required for .unwrap()
pub enum Error {
    NoSuchDevice,
    IllegalAction,              /* returned when a method is called when in the wrong state (e.g. start() when already active) */
    RustPcapError(pcap::Error),
    FilterError(String),
    ParsingError(etherparse::ReadError),
    DisconnectedThread,
    InternalError
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
    pub output : String,            // will need to be changed
    sender: Option<Sender<Command>>
}

impl APMFSniffer {

    fn new(device : Device, status : Status, output : String) -> Self {
        APMFSniffer{device, capture : None, status, output, sender: None}
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
        self.start_capture_thread(active_cap);

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
            .immediate_mode(true)               // packets are picked up immediately (no buffering)
            //cap.rfmon(true);                                      // might be important for wlan
            .open()?;

        capture.filter(filter, false)?;

        Ok(capture)
    }

    fn start_capture_thread(&mut self, mut cap: Capture<Active>) {
        let (sender, receiver): (Sender<Command>, Receiver<Command>) = channel();
        self.sender = Some(sender);
        thread::spawn(move || {
            while gib_test(&mut cap).is_ok() { // this should make the thread automatically stop if the sender disconnects
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
        });
    }
}

impl Drop for APMFSniffer {
    fn drop(&mut self) {
        if self.sender.is_none() {
            return;
        }
        self.sender.as_ref().unwrap().send(Command::Stop);
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
pub fn init(dev_name : &str) -> Result<APMFSniffer, Error> {

    let list = Device::list()?;        // can return MalformedError, PcapError, InvalidString

    for dev in list {
        if dev.name == dev_name {
            return Ok(APMFSniffer::new(dev, Initialized, "stdout?".to_string()))
        }
    }

    Err(NoSuchDevice)
}

pub fn list_devices() -> Result<Vec<String>, Error> {
    let list = Device::list()?;      // can return MalformedError, PcapError, InvalidString
    return Ok(list.into_iter().map(|d| d.name).collect());
}

fn gib_test(cap: &mut Capture<Active>) -> Result<(), Error> {

    let p = cap.next()?;

    /* let's try to show an IP packet */
    let packet = p.data;

    println!("len: {}", packet.len());
    let net_and_transport = SlicedPacket::from_ethernet(&packet)?;
    match net_and_transport.ip {
        Some(InternetSlice::Ipv4(ip, ..)) => {
            println!("\tsrc addr: {}", ip.source_addr());
            println!("\tdst addr: {}", ip.destination_addr());
        },
        Some(InternetSlice::Ipv6(ip, ..)) => {
            println!("\tsrc addr: {}", ip.source_addr());
            println!("\tdst addr: {}", ip.destination_addr());
        },
        _ => {}
    }
    match net_and_transport.transport {
        Some(TransportSlice::Udp(udp)) => {
            println!("\t src port: {}", udp.source_port());
            println!("\t dst port: {}", udp.destination_port());
        },
        Some(TransportSlice::Tcp(tcp)) => {
            println!("\t src port: {}", tcp.source_port());
            println!("\t dst port: {}", tcp.destination_port());
        },
        _ => {}
    }


    Ok(())
}

struct APMFPacket {
    src_addr:
}


