// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.txt

pub use crate::headers::ip_header::IPHeader;
pub use crate::headers::tcp_header::TCPHeader;

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,
    pub data: [u8; 1504],

}

impl Packet {

    pub fn parse(data: [u8; 1504], bytes_read: usize) -> Option<Packet> {

        let eth_flags: u16 = u16::from_be_bytes([data[0], data[1]]);    // First 2 bytes are TUN/TAP flags
        let eth_proto: u16 = u16::from_be_bytes([data[2], data[3]]);    // Second 2 bytes are TUN/TAP proto

        if eth_proto != 0x0800 {
            // Skip if not IPv4
            return None;
        }

        // Parse internet header
        let ip_header = IPHeader::parse(&data[4 .. bytes_read]);

        if !ip_header.validate() {
            // Skip if internet header is invalid
            return None;
        }

        // Slice bytes containing TCP header
        let tcp_header_bytes = &data[4 + ip_header.header_length as usize .. 4 + ip_header.total_length as usize];

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
                data,
            }
        )

    }

    pub fn get_tcp_data(&self) -> &[u8] {

        // From TUN/TAP data length + data offset to TUN/TAP data length to packet end
        &self.data[4 + self.tcp_header.data_offset as usize .. 4 + self.ip_header.total_length as usize]

    }

}