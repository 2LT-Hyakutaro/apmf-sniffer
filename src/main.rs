use apmf_sniffer::*;
use clap::Parser;


#[derive(Parser, Debug, PartialEq)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Flag for listing devices
    #[clap(short, long, value_parser, default_value_t = false)]
    list: bool,

    /// Flag for capturing on device <DEV_NAME>
    #[clap(short, long, value_parser, default_value_t = false)]
    capture: bool,

    /// Name of the device to capture on
    #[clap(short, long = "dev", value_parser)]
    dev_name: Option<String>,

    /// BPF string for capture filter
    #[clap(short, long, value_parser, default_value = "")]
    filter: String,
}

fn main() {

    let args = Args::parse();
    let mut device;

    match args {
        Args{ list: true, capture: false, dev_name:None, filter: a } if a.as_str() == "" => {
            let list = list_devices();
            if list.is_err() {
                println!("Could not get list of available devices: Error {:?}", list.err().unwrap());
                return;
            }
            println!("{:?}", list.unwrap());
            return;
        },
        Args{ list: false, capture: true, dev_name:Some(dev), filter: f } => {
            let d = init(dev.as_str(), f.as_str());
            if d.is_err() {
                println!("Could not initialize device {}: Error {:?}", dev, d.err().unwrap());
                return;
            }
            device = d.unwrap();
            println!("Initialized device {}", dev);

            let res = device.start();
            if res.is_err() {
                println!("Could not start capture on device {}: Error {:?}", dev, res.err().unwrap());
                return;
            }
            println!("Started capture on dev {}", dev)
        },
        _ => {
            println!("Invalid combination of parameters");
            return;
        }
    }

    while device.gib().is_ok() {}
    println!("gib() returned with error");

}