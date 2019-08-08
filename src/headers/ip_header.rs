// Internet Protocol header
// https://tools.ietf.org/html/rfc791

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version|  IHL  |Type of Service|          Total Length         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Identification        |Flags|      Fragment Offset    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Time to Live |    Protocol   |         Header Checksum       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Source Address                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Destination Address                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::headers::tcp_header::TCPHeader;

#[derive(Debug)]
pub struct IPHeader {

    pub bytes: Vec<u8>,

    pub version: u8,            // Internet header version (should be 4)
    pub total_length: u16,      // Whole packet length
    pub header_length: u8,      // Header length in bytes
    pub source_address: u32,
    pub destination_address: u32,
    pub options: Vec<u8>,

}

#[derive(Debug)]
pub struct IPHeaderBuilder {

    pub source_address: u32,
    pub destination_address: u32,
    pub options: Vec<u8>,

}

impl IPHeader {

    pub fn parse(bytes: &[u8]) -> IPHeader {

        let header_length = (bytes[0] & 0xF) * 4;

        IPHeader {
            bytes: bytes[.. header_length as usize].to_vec(),
            version: (bytes[0] & 0xF0) >> 4,
            header_length,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            source_address: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            destination_address: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            options: vec!(),
        }

    }

    pub fn validate(&self) -> bool {

        self.version == 4 &&
        self.header_length >= 20 &&
        self.total_length >= self.header_length as u16

    }

    pub fn get_source_address_str(&self) -> String {
        format!("{}.{}.{}.{}",
            (self.source_address & 0xFF000000) >> 24,
            (self.source_address & 0x00FF0000) >> 16,
            (self.source_address & 0x0000FF00) >> 8,
            (self.source_address & 0x000000FF),
        )
    }

    pub fn get_destination_address_str(&self) -> String {
        format!("{}.{}.{}.{}",
            (self.destination_address & 0xFF000000) >> 24,
            (self.destination_address & 0x00FF0000) >> 16,
            (self.destination_address & 0x0000FF00) >> 8,
            (self.destination_address & 0x000000FF),
        )
    }

    pub fn get_data_length(&self) -> u16 {
        self.total_length - self.header_length as u16
    }

    pub fn get_bytes(&self) -> &[u8] {

        &self.bytes[.. self.header_length as usize]

    }

}

impl IPHeaderBuilder {

    pub fn new() -> IPHeaderBuilder {

        IPHeaderBuilder {
            source_address: 0,
            destination_address: 0,
            options: vec!(),
        }

    }

    pub fn build(&self, tcp_header: &TCPHeader, data_length: u16) -> IPHeader {

        let padding = (4 - self.options.len() % 4) % 4;
        let mut header_length = 20 + self.options.len() + padding;
        let total_length = header_length as u16 + data_length + tcp_header.data_offset as u16;

        let total_length_bytes = total_length.to_be_bytes();
        let source_address = self.source_address.to_be_bytes();
        let destination_address = self.destination_address.to_be_bytes();

        let mut bytes: Vec<u8> = vec!(
            0b01000000 + (header_length as u8 / 4), 0, total_length_bytes[0], total_length_bytes[1],
            0, 0, 0, 0,
            0, 0, 0, 0,
            source_address[0], source_address[1], source_address[2], source_address[3],
            destination_address[0], destination_address[1], destination_address[2], destination_address[3],
        );

        for &option in self.options.iter() {
            bytes.push(option);
        }

        if padding > 0 {
            for i in 0 .. padding {
                bytes.push(0);
            }
        }

        IPHeader {
            bytes,
            version: 4,
            header_length: header_length as u8,
            total_length,
            source_address: self.source_address,
            destination_address: self.destination_address,
            options: self.options.clone(),
        }

    }

}