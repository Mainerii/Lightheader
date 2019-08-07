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

#[derive(Debug)]
pub struct IPHeader {

    pub version: u8,            // Internet header version (should be 4)
    pub total_length: u16,      // Whole packet length
    pub header_length: u8,      // Header length in bytes
    pub source_address: u32,
    pub destination_address: u32,

}

#[derive(Debug)]
pub struct IPHeaderBuilder {

    pub source_address: u32,
    pub destination_address: u32,

}

impl IPHeader {

    pub fn parse(bytes: &[u8]) -> IPHeader {

        IPHeader {
            version: (bytes[0] & 0xF0) >> 4,
            header_length: (bytes[0] & 0xF) * 4,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            source_address: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            destination_address: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
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

}

impl IPHeaderBuilder {

    pub fn new() -> IPHeaderBuilder {

        IPHeaderBuilder {
            source_address: 0,
            destination_address: 0,
        }

    }

    pub fn build(&self, data_length: u16) -> IPHeader {

        IPHeader {
            version: 4,
            header_length: 0,
            total_length: 0,
            source_address: 0,
            destination_address: 0,
        }

    }

}