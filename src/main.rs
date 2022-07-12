use apmf_sniffer::*;

fn main() {

    let sniffer = init("bluetooth0");

    if  sniffer.is_err(){
        println!("No such device");
    }
    else {
        println!("Using sniffer: {:?}", sniffer.unwrap());
    }


}