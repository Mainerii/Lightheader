pub use crate::headers::ip_header::IPHeader;
pub use crate::headers::tcp_header::TCPHeader;

pub struct Packet {

    pub ip_header: IPHeader,
    pub tcp_header: TCPHeader,

}

impl Packet {

    pub fn parse(bytes: &[u8]) -> Packet {

        Packet {
            ip_header: IPHeader::parse(bytes),
            tcp_header: TCPHeader::parse(&bytes[..]),
        }

    }

    pub fn validate(&self) -> bool {

        true

    }

}