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
            return Err(GenericErr);             // could use an error message
        }

        let cap = res_cap.unwrap();
        cap.promisc(true);

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