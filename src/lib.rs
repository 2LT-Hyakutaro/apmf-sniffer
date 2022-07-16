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
    RustPcapError(String),
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
}

impl APMFSniffer {

    fn new(device : Device, status : Status, output : String) -> Self {
        APMFSniffer{device, capture : None, status, output}
    }

    pub fn start(&mut self) -> Result<(), Error> {

        if self.status != Initialized {
            return Err(IllegalAction);
        }

        let res_cap = Capture::from_device(self.device.name.as_str());

        if res_cap.is_err() {
            return Err(RustPcapError(format!("{:?}", res_cap.err().unwrap())));
        }

        let res_active = res_cap.unwrap().promisc(true)
            .immediate_mode(true)               // packets are picked up immediately (no buffering)
            //cap.rfmon(true);                                      // might be important for wlan
            .open();

        if res_active.is_err() { return Err(RustPcapError(format!("{:?}", res_active.err().unwrap()))); }

        self.capture = Some(res_active.unwrap());

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

        println!("{:?}", r.unwrap().header);
        Ok(())
    }
}
pub fn init(dev_name : &str) -> Result<APMFSniffer, Error> {

    let list = Device::list();
    if list.is_err() {
        return Err(GenericErr);
    }

    for dev in list.unwrap() {
        if dev.name == dev_name {
            return Ok(APMFSniffer::new(dev, Initialized, "stdout?".to_string()))
        }
    }

    Err(NoSuchDevice)
}

pub fn list_devices() -> Result<Vec<String>, Error> {
    let list = Device::list();
    if list.is_err() {
        return Err(GenericErr);
    }
    return Ok(list.unwrap().into_iter().map(|d| d.name).collect());
}