use std::cmp::{max, min};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use crate::APMFPacket;

struct Report {
    report: HashMap<ReportHeader, ReportInfo>,
}

impl Report {
    fn insert_packet(&mut self, p: APMFPacket) {
        let p_header = ReportHeader {
            src_addr: p.src_addr,
            src_port: p.src_port,
            dest_addr: p.dest_addr,
            dest_port: p.dest_port
        };
        if self.report.contains_key(&p_header) {
            let mut info = self.report.get_mut(&p_header).unwrap();
            info.start_time = min(info.start_time, p.timestamp);
            info.stop_time = max(info.stop_time, p.timestamp);
            info.n_bytes += p.n_bytes;
            info.protocols.push(p.protocol);
        }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "src address\tsrc port\tdest address\tdest port\ttime first packet\ttime last packet\tprotocols transported\tnumber of bytes\n")?;
        for (header, info) in self.report.iter() {
            write!(f, "{}\t{}\t{}\t{}\t", header.src_addr, header.src_port, header.dest_addr, header.dest_port)?;
            write!(f, "{}\t{}\t{}\t{}\n", info.start_time, info.stop_time, info.protocols.join(", "), info.n_bytes)?;
        }

        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash)]
struct ReportHeader {
    src_addr: IpAddr,
    dest_addr: IpAddr,
    src_port: u16,
    dest_port: u16,
}
struct ReportInfo {
    start_time: u128,
    stop_time: u128,
    n_bytes: u32,
    protocols: Vec<&'static str>
}

fn generate_report(packets: Vec<APMFPacket>) -> Report {
    let mut report = Report {
        report: HashMap::new()
    };

    for p in packets {
        report.insert_packet(p);
    }

    return report;
}
