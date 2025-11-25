use crate::discv4::messages::{Message, Packet, PacketDecodeErr};

use bytes::BytesMut;
use secp256k1::SecretKey;
use tokio_util::codec::{Decoder, Encoder};
use tracing::info;

#[derive(Debug)]
pub struct Discv4Codec {
    signer: SecretKey,
}

impl Discv4Codec {
    pub fn new(signer: SecretKey) -> Self {
        Self { signer }
    }
}

impl Decoder for Discv4Codec {
    type Item = Packet;
    type Error = PacketDecodeErr;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        info!("Decoding packet from buffer of length {}", buf.len());
        if !buf.is_empty() {
            Ok(Some(Packet::decode(&buf.split_to(buf.len()))?))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Message> for Discv4Codec {
    type Error = PacketDecodeErr;

    fn encode(&mut self, message: Message, buf: &mut BytesMut) -> Result<(), Self::Error> {
        info!("Encoding packet into buffer of length {}", buf.len());
        message.encode_with_header(buf, &self.signer);
        Ok(())
    }
}
