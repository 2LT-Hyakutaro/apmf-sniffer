use apmf_sniffer::*;

fn main() {

    if let Err(_e) = init("bluetooth0") {
        println!("No such device");
    }
    else {
        println!("Using device ***");
    }


}