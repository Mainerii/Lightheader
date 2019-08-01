pub mod packet;
pub mod headers;

#[cfg(test)]
mod tests {

    use crate::packet::Packet;

    #[test]
    fn test_parsing() {

        let request: [u8; 52] = [
            0, 0, 134, 221, 96, 0, 0, 0, 0, 8, 58,
            255, 254, 128, 0, 0, 0, 0, 0, 0, 224,
            121, 253, 166, 50, 66, 149, 211, 255,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 2, 133, 0, 215, 0, 0, 0, 0, 0
        ];

        let request_packet = Packet::parse(&request);

        assert_eq!(request_packet.validate(), true);

    }

}
