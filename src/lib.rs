use pcap::{Capture, Device, Active};
use crate::Error::*;
use crate::Status::{Sniffing, Initialized, Paused};

#[cfg(test)]
mod tests {

}

#[derive(Debug)]                // required for .unwrap()
pub enum Error {
    GenericErr,
    NoSuchDevice,
    IllegalAction,              /* returned when a method is called when in the wrong state (e.g. start() when already active) */
    RustPcapError(pcap::Error),
}

impl From<pcap::Error> for Error {
    fn from(e: pcap::Error) -> Self {
        RustPcapError(e)
    }
}
#[derive(Debug, PartialEq)]
pub enum Status {
    Uninitialized,
    Initialized,
    Sniffing,
    Paused
}


pub struct APMFSniffer {
    pub device : Device,
    pub capture : Option<Capture<Active>>,
    pub status : Status,
    pub output : String,            // will need to be changed
    pub filter : String,
}

impl APMFSniffer {

    fn new(device : Device, status : Status, output : String, bpf : &str) -> Self {
        APMFSniffer{device, capture : None, status, output, filter : bpf.to_string()}
    }

    pub fn start(&mut self) -> Result<(), Error> {

        if self.status != Initialized {
            return Err(IllegalAction);
        }

        let res_cap = Capture::from_device(self.device.name.as_str())?;

        let res_active = res_cap.promisc(true)
            .immediate_mode(true)               // packets are picked up immediately (no buffering)
            //cap.rfmon(true);                                      // might be important for wlan
            .open()?;

        self.capture = Some(res_active);
        self.capture.as_mut().unwrap().filter(self.filter.as_str(), false)?;

        self.status = Sniffing;

        return Ok(());
    }

    pub fn pause(&mut self) -> Result<(), Error> {
        return if self.status == Sniffing {
            self.status = Paused;
            Ok(())
        } else {
            Err(IllegalAction)
        }
    }

    pub fn gib(&mut self) -> Result<(), Error> {

        let r = self.capture.as_mut().unwrap().next();
        if r.is_err() { return Err(GenericErr)};

        /* let's try to show an IP packet */
        let packet = r.unwrap().data;
        if packet.len() >= 34 {
            let mac_dest = &packet[0..6];
            let mac_src = &packet[6..12];
            let ether_type = &packet[12..14];

            if ether_type[0] == 0x08 && ether_type[1] == 0{
                let ip_src = &packet[26..30];
                let ip_dest = &packet[30..34];

                println!("len: {}", packet.len());
                println!("\tMAC src: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
                println!("\tMAC dest: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", mac_dest[0], mac_dest[1], mac_dest[2], mac_dest[3], mac_dest[4], mac_dest[5]);
                println!("\tIP src: {}.{}.{}.{}", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
                println!("\tIP dest: {}.{}.{}.{}", ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3]);
            }
        }

        Ok(())
    }
}

pub fn init(dev_name : &str, bpf : &str) -> Result<APMFSniffer, Error> {

    let list = Device::list()?;        // can return MalformedError, PcapError, InvalidString


    for dev in list {
        if dev.name == dev_name {
            return Ok(APMFSniffer::new(dev, Initialized, "stdout?".to_string(), bpf))
        }
    }


    Err(NoSuchDevice)
}

pub fn list_devices() -> Result<Vec<String>, Error> {
    let list = Device::list();      // can return MalformedError, PcapError, InvalidString
    if list.is_err() {
        return Err(GenericErr);
    }
    return Ok(list.unwrap().into_iter().map(|d| d.name).collect());
}