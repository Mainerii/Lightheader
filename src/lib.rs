pub mod packet;
pub mod headers;

#[cfg(test)]
mod tests {

    use crate::packet::Packet;

    #[test]
    fn test_request_parsing() {

        let request: [u8; 52] = [
            0, 0, 8, 0, 69, 0, 0, 60, 22, 108,
            64, 0, 64, 6, 162, 203, 192, 168, 0,
            50, 192, 168, 0, 2, 129, 218, 1, 187, 71,
            198, 111, 179, 0, 0, 0, 0, 160, 2, 250, 240,
            43, 183, 22, 212, 0, 0, 0, 0, 1, 3, 3, 7
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

        assert_eq!(request_packet.tcp_header.source_port, 33242);
        assert_eq!(request_packet.tcp_header.destination_port, 443);
        assert_eq!(request_packet.tcp_header.sequence_number, 1204187059);
        assert_eq!(request_packet.tcp_header.acknowledgement_number, 0);
        assert_eq!(request_packet.tcp_header.data_offset, 40);
        assert_eq!(request_packet.tcp_header.urg, false);
        assert_eq!(request_packet.tcp_header.ark, false);
        assert_eq!(request_packet.tcp_header.psh, false);
        assert_eq!(request_packet.tcp_header.rst, false);
        assert_eq!(request_packet.tcp_header.syn, true);
        assert_eq!(request_packet.tcp_header.fin, false);
        assert_eq!(request_packet.tcp_header.window, 64240);

    }

}
