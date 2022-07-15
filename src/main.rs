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
}

fn main() {

    let args = Args::parse();
    let mut device;

    match args {
        Args{ list: true, capture: false, dev_name:None } => {
            let list = list_devices();
            if list.is_err() {
                println!("Could not get list of available devices");
                return;
            }
            println!("{:?}", list.unwrap());
        },
        Args{ list: false, capture: true, dev_name:Some(dev) } => {
            let d = init(dev.as_str());
            if d.is_err() {
                println!("Could not initialize device {}", dev);
                return;
            }
            device = d.unwrap();
            println!("Initialized device {}", dev);

            if device.start().is_err() {
                println!("Could not start capture on device {}", dev);
                return;
            }
            println!("Started capture on dev {}", dev)
        },
        _ => println!("Invalid combination of parameters")
    }

/*
    let r = init("bluetooth0");

    if  r.is_err(){
        println!("No such device");
    }
    else {
        println!("Using sniffer: {:?}", r.as_ref().unwrap().device);
    }

    let mut sniffer = r.unwrap();

    sniffer.start().expect("first start should not panic");
    sniffer.start().expect_err("second start should not be ok");
    sniffer.pause().expect("first pause should not panic");
    sniffer.pause().expect_err("second pause should not be ok");
*/
}