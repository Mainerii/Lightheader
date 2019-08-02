pub use crate::headers::ip_header::IPHeader;
pub use crate::headers::tcp_header::TCPHeader;

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,

}

impl Packet {

    pub fn parse(bytes: &[u8], bytes_read: usize) -> Option<Packet> {

        let ip_header = IPHeader::parse(bytes);
        if !ip_header.validate() { () }

        let tcp_header = TCPHeader::parse(&bytes[ip_header.header_length as usize .. bytes_read]);
        if !tcp_header.validate() { () }

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