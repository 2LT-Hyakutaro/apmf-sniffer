use pcap::Device;
use crate::Error::*;

#[cfg(test)]
mod tests {

}

pub enum Error {
    GenericErr,
    NoSuchDevice,
}

pub fn init(dev_name : &str) -> Result<(), Error> {

    let list = Device::list();
    if list.is_err() {
        return Err(GenericErr);
    }

    for dev in list.unwrap() {
        if dev.name == dev_name {
            return Ok(())
        }
    }

    Err(NoSuchDevice)
}