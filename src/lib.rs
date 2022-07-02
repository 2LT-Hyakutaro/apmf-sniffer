use pcap::Device;

#[cfg(test)]
mod tests {
    use crate::init;

    #[test]
    fn test_init() {
        init();
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

fn init() -> Result<(), pcap::Error> {
    let list = Device::list()?;
    println!("{:?}", list.iter().map(|x|x.name.clone()).collect::<Vec<String>>());
    Ok(())
}