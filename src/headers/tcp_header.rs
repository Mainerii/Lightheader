// Transmission Control Protocol header
// https://tools.ietf.org/html/rfc793
// https://www.netfor2.com/tcpsum.htm

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Sequence Number                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Acknowledgment Number                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Data |           |U|A|P|R|S|F|                               |
//  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//  |       |           |G|K|H|T|N|N|                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |         Urgent Pointer        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             data                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::headers::ip_header::{IPHeader, IPHeaderBuilder};

use std::vec::Vec;

#[derive(Debug)]
pub struct TCPHeader {

    pub bytes: Vec<u8>,

    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,

}

pub struct TCPHeaderBuilder {

    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,

}

impl TCPHeader {

    pub fn parse(ip_header: &IPHeader, bytes: &[u8]) -> Option<TCPHeader> {

        let data_offset = ((bytes[12] & 0xF0) >> 4) * 4;
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);

        if checksum != TCPHeader::calculate_checksum(ip_header.source_address, ip_header.destination_address, bytes) {
            // Cancel if invalid checksum
            return None;
        }

        Some(
            TCPHeader {
                bytes: bytes[.. data_offset as usize - 1].to_vec(),
                source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
                destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
                sequence_number: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                acknowledgement_number: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                urg: (bytes[13] & 0b00100000) >> 5 == 1,
                ack: (bytes[13] & 0b00010000) >> 4 == 1,
                psh: (bytes[13] & 0b00001000) >> 3 == 1,
                rst: (bytes[13] & 0b00000100) >> 2 == 1,
                syn: (bytes[13] & 0b00000010) >> 1 == 1,
                fin: (bytes[13] & 0b00000001) == 1,
                window: u16::from_be_bytes([bytes[14], bytes[15]]),
                checksum,
                urgent_ptr: u16::from_be_bytes([bytes[18], bytes[19]]),
                options: Vec::new(),
                data_offset,
            }
        )

    }

    pub fn calculate_checksum(source_address: u32, destination_address: u32, bytes: &[u8]) -> u16 {

        let data_length = bytes.len();
        let padding = data_length % 2;

        let mut sum: u32 = 0;

        // Calculate sum of all TCP bytes as 16 bit words
        for i in (0 .. data_length - padding).step_by(2) {
            if i == 16 {
                // Skip checksum
                continue
            }
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        }

        if padding == 1 {
            sum += u16::from_be_bytes([bytes[data_length - 1], 0x0]) as u32;
        }

        // Add pseudo header sum
        sum += source_address >> 16;                // Highest 2 bytes of source address
        sum += source_address & 0xFFFF;             // Lowest 2 bytes of source address
        sum += destination_address >> 16;           // Highest 2 bytes of destination address
        sum += destination_address & 0xFFFF;        // Lowest 2 bytes of destination address
        sum += 6 + bytes.len() as u32;              // TCP protocol number + TCP data length

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16

    }

    pub fn get_bytes(&self) -> &[u8] {

        &self.bytes[.. self.data_offset as usize]

    }

}

impl TCPHeaderBuilder {

    pub fn new() -> TCPHeaderBuilder {

        TCPHeaderBuilder {
            source_port: 0,
            destination_port: 0,
            sequence_number: 0,
            acknowledgement_number: 0,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
            window: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }

    }

    pub fn build(&self, ip_header_builder: &IPHeaderBuilder, data: &[u8]) -> Option<TCPHeader> {

        let padding = (4 - self.options.len() % 4) % 4;
        let data_offset = 20 + self.options.len() + padding;

        let source_port = self.source_port.to_be_bytes();
        let destination_port = self.destination_port.to_be_bytes();
        let sequence_number = self.sequence_number.to_be_bytes();
        let acknowledgement_number = self.acknowledgement_number.to_be_bytes();
        let window = self.window.to_be_bytes();
        let urgent_ptr = self.urgent_ptr.to_be_bytes();

        let mut flags: u8 = 0;
        flags += (self.urg as u8) << 5;
        flags += (self.ack as u8) << 4;
        flags += (self.psh as u8) << 3;
        flags += (self.rst as u8) << 2;
        flags += (self.syn as u8) << 1;
        flags += self.fin as u8;

        let mut bytes: Vec<u8> = vec!(
            source_port[0], source_port[1], destination_port[0], destination_port[1],
            sequence_number[0], sequence_number[1], sequence_number[2], sequence_number[3],
            acknowledgement_number[0], acknowledgement_number[1], acknowledgement_number[2], acknowledgement_number[3],
            ((data_offset / 4) << 4) as u8, flags, window[0], window[1],
            0, 0, urgent_ptr[0], urgent_ptr[1],
        );

        for &option in self.options.iter() {
            bytes.push(option);
        }

        if padding > 0 {
            for _ in 0 .. padding {
                bytes.push(0);
            }
        }

        let mut tcp_section = bytes.clone();
        tcp_section.extend_from_slice(data);

        let checksum = TCPHeader::calculate_checksum(ip_header_builder.source_address, ip_header_builder.destination_address, &tcp_section[..]);
        let checksum_bytes = checksum.to_be_bytes();

        bytes[16] = checksum_bytes[0];
        bytes[17] = checksum_bytes[1];

        Some (
            TCPHeader {
                bytes,
                source_port: self.source_port,
                destination_port: self.destination_port,
                sequence_number: self.sequence_number,
                acknowledgement_number: self.acknowledgement_number,
                data_offset: data_offset as u8,
                urg: self.urg,
                ack: self.ack,
                psh: self.psh,
                rst: self.rst,
                syn: self.syn,
                fin: self.fin,
                window: self.window,
                checksum,
                urgent_ptr: self.urgent_ptr,
                options: self.options.clone(),
            }
        )

    }

}
