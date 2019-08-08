// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.txt

pub use crate::headers::ip_header::IPHeader;
pub use crate::headers::tcp_header::TCPHeader;
use crate::headers::ip_header::IPHeaderBuilder;
use crate::headers::tcp_header::TCPHeaderBuilder;

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,
    pub bytes: Vec<u8>,

}

pub struct PacketBuilder {

    pub ip_header_builder: IPHeaderBuilder,
    pub tcp_header_builder: TCPHeaderBuilder,
    pub bytes: Vec<u8>,

}

impl Packet {

    pub fn parse(bytes: [u8; 1504], bytes_read: usize) -> Option<Packet> {

        let eth_flags: u16 = u16::from_be_bytes([bytes[0], bytes[1]]);    // First 2 bytes are TUN/TAP flags
        let eth_proto: u16 = u16::from_be_bytes([bytes[2], bytes[3]]);    // Second 2 bytes are TUN/TAP proto

        if eth_proto != 0x0800 {
            // Skip if not IPv4
            return None;
        }

        // Parse internet header
        let ip_header = IPHeader::parse(&bytes[4 .. bytes_read]);

        if !ip_header.validate() {
            // Skip if internet header is invalid
            return None;
        }

        // Slice bytes containing TCP header
        let tcp_header_bytes = &bytes[4 + ip_header.header_length as usize .. 4 + ip_header.total_length as usize];

        // Parse TCP header
        let tcp_header = TCPHeader::parse(tcp_header_bytes);

        if !tcp_header.validate(&ip_header, tcp_header_bytes) {
            // Skip if TCP header is invalid
            return None;
        }

        Some(
            Packet {
                ip_header,
                tcp_header,
                bytes: (&bytes[4 .. bytes_read]).to_vec(),
            }
        )

    }

    pub fn get_bytes(&self) -> &[u8] {

        &self.bytes[.. self.ip_header.total_length as usize]

    }

    pub fn get_tcp_data(&self) -> &[u8] {

        // From TUN/TAP data length + data offset to TUN/TAP data length to packet end
        &self.bytes[self.ip_header.header_length as usize + self.tcp_header.data_offset as usize .. self.ip_header.total_length as usize]

    }

}

impl PacketBuilder {

    pub fn new() -> PacketBuilder {

        PacketBuilder {
            bytes: vec!(),
            ip_header_builder: IPHeaderBuilder::new(),
            tcp_header_builder: TCPHeaderBuilder::new(),
        }

    }

    pub fn build(&self) -> Packet {

        let tcp_header = self.tcp_header_builder.build(&self.ip_header_builder, &self.bytes[..]);
        let ip_header = self.ip_header_builder.build(&tcp_header, self.bytes.len() as u16);

        let mut bytes = vec!();
        bytes.extend_from_slice(ip_header.get_bytes());
        bytes.extend_from_slice(tcp_header.get_bytes());
        bytes.extend_from_slice(&self.bytes);

        Packet {
            bytes,
            ip_header,
            tcp_header,
        }

    }

}
