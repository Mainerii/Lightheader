// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.txt

use crate::headers::ip_header::{IPHeader, IPHeaderBuilder};
use crate::headers::tcp_header::{TCPHeader, TCPHeaderBuilder};

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,
    pub bytes: Vec<u8>,                             // All headers and data

}

pub struct PacketBuilder {

    pub ip_header_builder: IPHeaderBuilder,
    pub tcp_header_builder: TCPHeaderBuilder,
    pub bytes: Vec<u8>,                             // TCP-data only

}

impl Packet {

    pub fn parse(bytes: [u8; 1504], bytes_read: usize) -> Option<Packet> {

        //let eth_flags: u16 = u16::from_be_bytes([bytes[0], bytes[1]]);    // First 2 bytes are TUN/TAP flags
        let eth_proto: u16 = u16::from_be_bytes([bytes[2], bytes[3]]);      // Second 2 bytes are TUN/TAP proto

        if eth_proto != 0x0800 {
            // Skip if not IPv4
            return None;
        }

        // Parse internet header
        let ip_header = match IPHeader::parse(&bytes[4 .. bytes_read]) {
            Some(header) => header,
            None => return None,
        };

        // Slice bytes containing TCP header and parse it
        let tcp_header_bytes = &bytes[4 + ip_header.header_length as usize .. 4 + ip_header.total_length as usize];
        let tcp_header = match TCPHeader::parse(&ip_header, tcp_header_bytes) {
            Some(header) => header,
            None => return None,
        };

        let mut packet_bytes = vec![0x00, 0x00, 0x08, 0x00];
        packet_bytes.extend_from_slice(&bytes[4 .. bytes_read]);

        Some(
            Packet {
                ip_header,
                tcp_header,
                bytes: packet_bytes,
            }
        )

    }

    pub fn get_bytes(&self) -> &[u8] {

        &self.bytes[.. 4 + self.ip_header.total_length as usize]

    }

    pub fn get_tcp_data(&self) -> &[u8] {

        // From TUN/TAP data length + data offset to TUN/TAP data length to packet end
        &self.bytes[4 + self.ip_header.header_length as usize + self.tcp_header.data_offset as usize .. 4 + self.ip_header.total_length as usize]

    }

}

impl PacketBuilder {

    pub fn new() -> PacketBuilder {

        PacketBuilder {
            bytes: Vec::new(),
            ip_header_builder: IPHeaderBuilder::new(),
            tcp_header_builder: TCPHeaderBuilder::new(),
        }

    }

    pub fn build(&self) -> Option<Packet> {

        let tcp_header = match self.tcp_header_builder.build(&self.ip_header_builder, &self.bytes[..]) {
            Some(header) => header,
            None => return None,
        };

        let ip_header = match self.ip_header_builder.build(&tcp_header, self.bytes.len()) {
            Some(header) => header,
            None => return None,
        };

        let eth_header = [0x00, 0x00, 0x08, 0x00];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&eth_header);
        bytes.extend_from_slice(ip_header.get_bytes());
        bytes.extend_from_slice(tcp_header.get_bytes());
        bytes.extend_from_slice(&self.bytes);

        Some(
            Packet {
                bytes,
                ip_header,
                tcp_header,
            }
        )

    }

}
