use pcap::Device;
use crate::Error::*;
use crate::Status::Uninitialized;

#[cfg(test)]
mod tests {

}

#[derive(Debug)]                // required for .unwrap()
pub enum Error {
    GenericErr,
    NoSuchDevice,
}

#[derive(Debug)]
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
    output : String,
}

impl APMFSniffer {

    fn new(device : String, status : Status, output : String) -> Self {
        APMFSniffer{device, status, output}
    }
}
pub fn init(dev_name : &str) -> Result<APMFSniffer, Error> {

    let list = Device::list();
    if list.is_err() {
        return Err(GenericErr);
    }

    for dev in list.unwrap() {
        if dev.name == dev_name {
            return Ok(APMFSniffer::new(dev.name, Uninitialized, "stdout?".to_string()))
        }
    }

    Err(NoSuchDevice)
}