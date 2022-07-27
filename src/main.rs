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
    #[clap(long, value_parser, default_value = "")]
    filter: String,

    /// File to write the report on
    #[clap(short, long, value_parser)]
    file_name: Option<String>,

    /// Time (in milliseconds) after which a new report is generated in seconds
    #[clap(short, long, value_parser)]
    time: Option<u64>,
}

fn main() {

    let args = Args::parse();
    let mut device;

    match args {
        Args{ list: true, capture: false, dev_name:None, filter: a, file_name: None, time: None } if a.as_str() == "" => {
            let list = list_devices();
            if list.is_err() {
                println!("Could not get list of available devices: Error {:?}", list.err().unwrap());
                return;
            }
            list.unwrap().into_iter().for_each(|d| println!("{}", d));
            return;
        },
        Args{ list: false, capture: true, dev_name:Some(dev), filter: f, file_name: Some(file_name), time: Some(delta_t)  } => {
            // TODO: use file_name and delta_t
            let d = init(dev.as_str(), delta_t, file_name);
            if d.is_err() {
                println!("Could not initialize device {}: Error {:?}", dev, d.err().unwrap());
                return;
            }
            device = d.unwrap();
            println!("Initialized device {}", dev);

            let res = device.start(f.as_str());
            if res.is_err() {
                println!("Could not start capture on device {}: Error {:?}", dev, res.err().unwrap());
                return;
            }
            println!("Started capture on dev {}", dev);
        },
        Args{ list: false, capture: true, dev_name:None, filter: _, file_name: _, time: _  } => {
            println!("Error: Supply a device name");
            return;
        },
        Args{ list: false, capture: true, dev_name:_, filter: _, file_name: None, time: _  } => {
            println!("Error: Supply a file name");
            return;
        }
        Args{ list: false, capture: true, dev_name:_, filter: _, file_name: _, time: None  } => {
            println!("Error: Supply a time interval");
            return;
        }
        Args{ list: true, capture: true, dev_name:_, filter: _, file_name: _, time: _  } => {
            println!("Error: list and capture flag are mutually exclusive");
            return;
        }
        _ => {
            println!("Invalid combination of parameters");
            return;
        }
    }

    println!("Commands available:");
    println!("p - Pauses the capture process");
    println!("r - Resumes the capture process");
    println!("exit - Terminates the process, same as Ctrl+C");

    println!("Capturing packets... ");

    loop{
        let line = std::io::stdin().lines().next().unwrap().unwrap();
        match line.as_str() {
            "p" => {
                let res = device.pause();
                if res.is_err() {
                    match res.err().unwrap() {
                        Error::IllegalAction => println!("Cannot pause, sniffing not active"),
                        Error::DisconnectedThread => {
                            println!("Capture thread failed, quitting process");
                            return
                        },
                        _ => {
                            println!("Unexpected error");
                            return
                        }
                    }
                }

            },
            "r" => {
                let res = device.resume();
                if res.is_err() {
                    match res.err().unwrap() {
                        Error::IllegalAction => println!("Sniffing already active"),
                        Error::DisconnectedThread => {
                            println!("Capture thread failed, quitting process");
                            return
                        },
                        Error::InternalError => {
                            println!("Library internal error, quitting process");
                            return
                        },
                        _ => {
                            println!("Unexpected error");
                            return
                        }
                    }
                }
            },
            "exit" => {
                drop(device);
                return
            },
            _ => println!("Invalid command")
        }
    }
}