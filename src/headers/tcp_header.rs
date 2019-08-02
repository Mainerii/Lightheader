// Transmission Control Protocol header
// https://tools.ietf.org/html/rfc793

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

#[derive(Debug)]
pub struct TCPHeader {

    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,                // Beginning of the data in bytes
    pub urg: bool,
    pub ark: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
    pub window: u16,

}

impl TCPHeader {

    pub fn parse(bytes: &[u8]) -> TCPHeader {

        TCPHeader {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence_number: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            acknowledgement_number: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            data_offset: ((bytes[12] & 0xF0) >> 4) * 4,
            urg: (bytes[13] & 0b00100000) >> 5 == 1,
            ark: (bytes[13] & 0b00010000) >> 4 == 1,
            psh: (bytes[13] & 0b00001000) >> 3 == 1,
            rst: (bytes[13] & 0b00000100) >> 2 == 1,
            syn: (bytes[13] & 0b00000010) >> 1 == 1,
            fin: (bytes[13] & 0b00000001) == 1,
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
        }

    }

    pub fn validate(&self) -> bool {

        true

    }

}

