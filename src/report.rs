use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use crate::{APMFPacket, Port};

struct Report {
    report: HashMap<ReportHeader, ReportInfo>,
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
    trans_protocols: HashSet<&'static str>,
    app_protocols: Vec<Port> // need to change to HashSet as well (as we currently get the protocol, the protocol will be just one)
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
            info.trans_protocols.push(p.protocol);
            info.app_protocols.push(p.application);
        }
        else {
            self.report.insert(p_header, ReportInfo{
                start_time: p.timestamp,
                stop_time: p.timestamp,
                n_bytes: p.n_bytes,
                trans_protocols: HashSet::from([p.protocol]),
                app_protocols: vec![p.application]
            });
        }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "src address\tsrc port\tdest address\tdest port\ttime first packet\ttime last packet\tnumber of bytes\ttransport protocol\tapplication protocol\n")?;
        for (header, info) in self.report.iter() {
            let trans_p = info.trans_protocols.iter().collect::<Vec<&str>>().join(", ");
            let app_p = info.app_protocols.iter().map(|p| format!("{:?}", p)).collect::<Vec<String>>().join(", ");
            write!(f, "{}\t{}\t{}\t{}\t", header.src_addr, header.src_port, header.dest_addr, header.dest_port)?;
            write!(f, "{}\t{}\t{}\t{}\t{}\n", info.start_time, info.stop_time, info.n_bytes, trans_p, app_p)?;
        }

        Ok(())
    }
}

pub fn generate_report(packets: Vec<APMFPacket>) -> Report {
    let mut report = Report {
        report: HashMap::new()
    };

    for p in packets {
        report.insert_packet(p);
    }

    return report;
}
