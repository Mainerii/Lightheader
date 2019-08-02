pub mod packet;
pub mod headers;

#[cfg(test)]
mod tests {

    use crate::packet::Packet;

    #[test]
    fn test_request_parsing() {

        let request: [u8; 64] = [
            0, 0, 8, 0, 69, 0, 0, 60, 204, 139,
            64, 0, 64, 6, 236, 171, 192, 168, 0, 50,
            192, 168, 0, 2, 235, 224, 1, 187, 195, 42,
            208, 195, 0, 0, 0, 0, 160, 2, 250, 240, 69,
            39, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 41,
            213, 219, 3, 0, 0, 0, 0, 1, 3, 3, 7
        ];

        let request_packet = Packet::parse(&request[4..]);

        assert_eq!(request_packet.ip_header.version, 4);
        assert_eq!(request_packet.ip_header.total_length, 60);
        assert_eq!(request_packet.ip_header.header_length, 20);
        assert_eq!(request_packet.ip_header.get_data_length(), 40);
        assert_eq!(request_packet.ip_header.source_address, 3232235570);
        assert_eq!(request_packet.ip_header.get_source_address_str(), "192.168.0.50");
        assert_eq!(request_packet.ip_header.destination_address, 3232235522);
        assert_eq!(request_packet.ip_header.get_destination_address_str(), "192.168.0.2");

    }

}
