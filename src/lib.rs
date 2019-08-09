pub mod packet;
pub mod headers;
//pub mod packet_builder;

#[cfg(test)]
mod tests {

    use crate::packet::{Packet, PacketBuilder};

    #[test]
    fn test_request_parsing() {

        const bytes_in: usize = 65;

        // These would be set by TUN/TAP in actual program
        let mut buffer: [u8; 1504] = [0; 1504];
        let bytes_read = bytes_in;

        // Fake TUN/TAP request
        let request: [u8; bytes_in] = [

            0x00, 0x00, 0x08, 0x00,                                     // TUN/TAP https://www.kernel.org/doc/Documentation/networking/tuntap.txt

            0x45, 0x00, 0x00, 0x3D, 0xE1, 0x28, 0x40, 0x00,             // Internet header
            0x40, 0x06, 0xD8, 0x0D, 0xC0, 0xA8, 0x00, 0x32,
            0xC0, 0xA8, 0x00, 0x02,

            0xB3, 0xDE, 0x01, 0xBB, 0x99, 0xAF, 0x23, 0x0B,             // TCP header
            0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, 0xFA, 0xF0,
            0xCC, 0xC8, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4,
            0x04, 0x02, 0x08, 0x0A, 0xC0, 0x1B, 0x8C, 0x50,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,

            0x40,                                                       // Data

        ];

        for (index, byte) in request.iter().enumerate() {
            buffer[index] = *byte;
        }

        let request_packet = Packet::parse(buffer, bytes_in);

        assert_eq!(request_packet.is_some(), true);
        let request_packet = request_packet.unwrap();

        assert_eq!(request_packet.ip_header.version, 4);
        assert_eq!(request_packet.ip_header.total_length, 61);
        assert_eq!(request_packet.ip_header.header_length, 20);
        assert_eq!(request_packet.ip_header.get_data_length(), 41);
        assert_eq!(request_packet.ip_header.source_address, 0xC0A80032);
        assert_eq!(request_packet.ip_header.get_source_address_str(), "192.168.0.50");
        assert_eq!(request_packet.ip_header.destination_address, 0xC0A80002);
        assert_eq!(request_packet.ip_header.get_destination_address_str(), "192.168.0.2");

        assert_eq!(request_packet.tcp_header.source_port, 46046);
        assert_eq!(request_packet.tcp_header.destination_port, 443);
        assert_eq!(request_packet.tcp_header.sequence_number, 2578391819);
        assert_eq!(request_packet.tcp_header.acknowledgement_number, 0);
        assert_eq!(request_packet.tcp_header.data_offset, 40);
        assert_eq!(request_packet.tcp_header.urg, false);
        assert_eq!(request_packet.tcp_header.ack, false);
        assert_eq!(request_packet.tcp_header.psh, false);
        assert_eq!(request_packet.tcp_header.rst, false);
        assert_eq!(request_packet.tcp_header.syn, true);
        assert_eq!(request_packet.tcp_header.fin, false);
        assert_eq!(request_packet.tcp_header.window, 64240);
        assert_eq!(request_packet.tcp_header.checksum, 0xCCC8);
        assert_eq!(request_packet.tcp_header.urgent_ptr, 0);

        assert_eq!(request_packet.get_tcp_data(), &[0x40]);

    }

    #[test]
    fn test_packet_building() {

        let mut packet_builder = PacketBuilder::new();

        packet_builder.ip_header_builder.source_address = 0xC0A80032;
        packet_builder.ip_header_builder.destination_address = 0xC0A80002;

        packet_builder.tcp_header_builder.source_port = 46046;
        packet_builder.tcp_header_builder.destination_port = 443;
        packet_builder.tcp_header_builder.sequence_number = 2578391819;
        packet_builder.tcp_header_builder.acknowledgement_number = 50;
        packet_builder.tcp_header_builder.urg = true;
        packet_builder.tcp_header_builder.ack = false;
        packet_builder.tcp_header_builder.psh = true;
        packet_builder.tcp_header_builder.rst = false;
        packet_builder.tcp_header_builder.syn = true;
        packet_builder.tcp_header_builder.fin = false;
        packet_builder.tcp_header_builder.window = 64240;
        packet_builder.tcp_header_builder.urgent_ptr = 50;
        packet_builder.tcp_header_builder.options.push(128);

        packet_builder.bytes.push(64);

        let packet = packet_builder.build();

        assert_eq!(packet.is_some(), true);
        let packet = packet.unwrap();

        let bytes: [u8; 45] = [

            0x45, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x00,             // Internet header
            0x00, 0x00, 0x39, 0x4D, 0xC0, 0xA8, 0x00, 0x32,
            0xC0, 0xA8, 0x00, 0x02,

            0xB3, 0xDE, 0x01, 0xBB, 0x99, 0xAF, 0x23, 0x0B,             // TCP header
            0x00, 0x00, 0x00, 0x32, 0x60, 0x2A, 0xFA, 0xF0,
            0xF0, 0x86, 0x00, 0x32, 0x80, 0x00, 0x00, 0x00,

            0x40,                                                       // Data

        ];

        assert_eq!(packet.get_bytes(), &bytes[..]);

    }

}
