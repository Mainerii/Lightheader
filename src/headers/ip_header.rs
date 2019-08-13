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

    pub version: u8,                // Should be 4
    pub total_length: u16,          // Whole packet length
    pub header_length: u8,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: u32,
    pub destination_address: u32,
    pub options: Vec<u8>,

}

#[derive(Debug)]
pub struct IPHeaderBuilder {

    pub source_address: u32,
    pub destination_address: u32,
    pub ttl: u8,
    pub options: Vec<u8>,

}

impl IPHeader {

    pub fn parse(bytes: &[u8]) -> Option<IPHeader> {

        let header_length = (bytes[0] & 0xF) * 4;

        if header_length < 20 {
            // Invalid header
            return None;
        }

        let protocol = bytes[9];

        if protocol != 6 {
            // Not TCP
            return None;
        }

        let ip_header = IPHeader {
            bytes: bytes[.. header_length as usize].to_vec(),
            version: (bytes[0] & 0xF0) >> 4,
            header_length,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            ttl: bytes[8],
            protocol,
            header_checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            source_address: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            destination_address: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            options: Vec::new(),
        };

        if ip_header.version == 4 && ip_header.header_length as u16 > ip_header.total_length {
            // Invalid header
            return None;
        }

        Some(ip_header)

    }

    pub fn calculate_checksum(bytes: &[u8]) -> u16 {

        let data_length = bytes.len();
        let padding = data_length % 2;

        let mut sum: u32 = 0;

        // Calculate sum of all TCP bytes as 16 bit words
        for i in (0 .. data_length - padding).step_by(2) {
            if i == 10 {
                // Skip checksum
                continue
            }
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        }

        if padding == 1 {
            sum += u16::from_be_bytes([bytes[data_length - 1], 0x0]) as u32;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16

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
            ttl: 0,
            options: Vec::new(),
        }

    }

    pub fn build(&self, tcp_header: &TCPHeader, data_length: usize) -> Option<IPHeader> {

        let options_length = self.options.len();

        if options_length > 4 {
            // Cancel if options too long
            return None;
        }

        let padding = (4 - options_length % 4) % 4;
        let header_length = 20 + options_length + padding;
        let total_length = header_length + data_length + tcp_header.data_offset as usize;

        if total_length > 1500 || header_length > total_length {
            // Cancel if packet too big
            return None;
        }

        let total_length_bytes = (total_length as u16).to_be_bytes();
        let source_address = self.source_address.to_be_bytes();
        let destination_address = self.destination_address.to_be_bytes();

        let mut bytes: Vec<u8> = vec!(
            0b01000000 + (header_length as u8 / 4), 0, total_length_bytes[0], total_length_bytes[1],
            0, 0, 0, 0,
            self.ttl, 6, 0, 0,
            source_address[0], source_address[1], source_address[2], source_address[3],
            destination_address[0], destination_address[1], destination_address[2], destination_address[3],
        );

        for &option in self.options.iter() {
            bytes.push(option);
        }

        if padding > 0 {
            for _ in 0 .. padding {
                bytes.push(0);
            }
        }

        let header_checksum = IPHeader::calculate_checksum(&bytes[..]);
        let header_checksum_bytes = header_checksum.to_be_bytes();

        bytes[10] = header_checksum_bytes[0];
        bytes[11] = header_checksum_bytes[1];

        Some(
            IPHeader {
                bytes,
                version: 4,
                header_length: header_length as u8,
                total_length: total_length as u16,
                header_checksum,
                ttl: self.ttl,
                protocol: 6,
                source_address: self.source_address,
                destination_address: self.destination_address,
                options: self.options.clone(),
            }
        )

    }

}