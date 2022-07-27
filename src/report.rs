use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use crate::{APMFPacket, Port};
use chrono::NaiveDateTime;

pub struct Report {
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
    start_time: (i64, u32),
    stop_time: (i64, u32),
    n_bytes: u32,
    trans_protocols: HashSet<&'static str>,
    app_protocols: HashSet<Port> // need to change to HashSet as well (as we currently get the protocol, the protocol will be just one)
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
            info.trans_protocols.insert(p.protocol);
            info.app_protocols.insert(p.application);
        }
        else {
            self.report.insert(p_header, ReportInfo{
                start_time: p.timestamp,
                stop_time: p.timestamp,
                n_bytes: p.n_bytes,
                trans_protocols: HashSet::from([p.protocol]),
                app_protocols: HashSet::from([p.application])
            });
        }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "src address,src port,dest address,dest port,time first packet,time last packet,number of bytes,transport protocol,application protocol\n")?;
        for (header, info) in self.report.iter() {
            let trans_p = info.trans_protocols.iter().map(|s| s.to_owned()).collect::<Vec<&str>>().join(", ");
            let app_p = info.app_protocols.iter().map(|p| format!("{}", p)).collect::<Vec<String>>().join(", ");
            let start_time = NaiveDateTime::from_timestamp(info.start_time.0, info.start_time.1).format("%Y-%m-%d %H:%M:%S.%f").to_string();
            let stop_time = NaiveDateTime::from_timestamp(info.stop_time.0, info.stop_time.1).format("%Y-%m-%d %H:%M:%S.%f").to_string();
            write!(f, "{},{},{},{},", header.src_addr, header.src_port, header.dest_addr, header.dest_port)?;
            write!(f, "{},{},{},{},{}\n", start_time, stop_time, info.n_bytes, trans_p, app_p)?;
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
