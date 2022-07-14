use apmf_sniffer::*;

fn main() {

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

}