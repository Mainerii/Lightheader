pub mod packet;
pub mod headers;

#[cfg(test)]
mod tests {

    use crate::packet::Packet;

    #[test]
    fn test_request_parsing() {

        let request: [u8; 65] = [

            0x00, 0x00, 0x08, 0x00,                                     // TUN/TAP https://www.kernel.org/doc/Documentation/networking/tuntap.txt

            0x45, 0x00, 0x00, 0x3C, 0xE1, 0x28, 0x40, 0x00,             // Internet header
            0x40, 0x06, 0xD8, 0x0E, 0xC0, 0xA8, 0x00, 0x32,
            0xC0, 0xA8, 0x00, 0x02,

            0xB3, 0xDE, 0x01, 0xBB, 0x99, 0xAF, 0x23, 0x0B,             // TCP header
            0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, 0xFA, 0xF0,
            0x0C, 0xCA, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
            0x04, 0x02, 0x08, 0x0A, 0xC0, 0x1B, 0x8C, 0x50,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
            0x00,

        ];

        let request_packet = Packet::parse(&request[4..], 52 - 4);

        assert_eq!(request_packet.is_some(), true);
        let request_packet = request_packet.unwrap();

        assert_eq!(request_packet.ip_header.version, 4);
        assert_eq!(request_packet.ip_header.total_length, 60);
        assert_eq!(request_packet.ip_header.header_length, 20);
        assert_eq!(request_packet.ip_header.get_data_length(), 40);
        assert_eq!(request_packet.ip_header.source_address, 3232235570);
        assert_eq!(request_packet.ip_header.get_source_address_str(), "192.168.0.50");
        assert_eq!(request_packet.ip_header.destination_address, 3232235522);
        assert_eq!(request_packet.ip_header.get_destination_address_str(), "192.168.0.2");

        assert_eq!(request_packet.tcp_header.source_port, 46046);
        assert_eq!(request_packet.tcp_header.destination_port, 443);
        assert_eq!(request_packet.tcp_header.sequence_number, 2578391819);
        assert_eq!(request_packet.tcp_header.acknowledgement_number, 0);
        assert_eq!(request_packet.tcp_header.data_offset, 40);
        assert_eq!(request_packet.tcp_header.urg, false);
        assert_eq!(request_packet.tcp_header.ark, false);
        assert_eq!(request_packet.tcp_header.psh, false);
        assert_eq!(request_packet.tcp_header.rst, false);
        assert_eq!(request_packet.tcp_header.syn, true);
        assert_eq!(request_packet.tcp_header.fin, false);
        assert_eq!(request_packet.tcp_header.window, 64240);
        assert_eq!(request_packet.tcp_header.checksum, 3274);

    }

}
