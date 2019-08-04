pub use crate::headers::ip_header::IPHeader;
pub use crate::headers::tcp_header::TCPHeader;

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,

}

impl Packet {

    pub fn parse(bytes: &[u8], bytes_read: usize) -> Option<Packet> {

        let ip_header = IPHeader::parse(bytes);
        if !ip_header.validate() { return None; }

        let tcp_header_bytes = &bytes[ip_header.header_length as usize .. ip_header.total_length as usize];
        let tcp_header = TCPHeader::parse(tcp_header_bytes);
        if !tcp_header.validate(&ip_header, tcp_header_bytes) { return None; }

        Some(
            Packet {
                ip_header,
                tcp_header,
            }
        )

    }

    pub fn validate(&self) -> bool {

        true

    }

}