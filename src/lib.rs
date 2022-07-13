use pcap::Device;
use crate::Error::*;
use crate::Status::{Active, Initialized, Paused, Uninitialized};

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
    Active,
    Paused
}

#[derive(Debug)]
pub struct APMFSniffer {
    device : String,
    status : Status,
    output : String,            // will need to be changed
}

impl APMFSniffer {

    fn new(device : String, status : Status, output : String) -> Self {
        APMFSniffer{device, status, output}
    }

    pub fn start(&mut self) -> Result<(), Error> {
        return if self.status == Initialized {
            self.status = Active;
            Ok(())
        } else {
            Err(IllegalAction)
        }
    }

    pub fn pause(&mut self) -> Result<(), Error> {
        return if self.status == Active {
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
            return Ok(APMFSniffer::new(dev.name, Initialized, "stdout?".to_string()))
        }
    }

    Err(NoSuchDevice)
}