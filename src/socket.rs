use futures::{future::poll_fn, ready};
use tokio::io::PollEvented;

use std::io;
use std::task::{Context, Poll};

pub struct Socket {
    io: PollEvented<pppoe::Socket>,
}

impl Socket {
    pub fn new(interface_name: &str) -> io::Result<Self> {
        Ok(Self {
            io: PollEvented::new(pppoe::Socket::on_interface(interface_name)?)?,
        })
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.io.get_ref().mac_address()
    }

    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        poll_fn(|ctx| self.poll_send(ctx, packet)).await
    }

    pub fn poll_send(&self, ctx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(ctx))?;

        match self.io.get_ref().send(packet) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(ctx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|ctx| self.poll_recv(ctx, buf)).await
    }

    pub fn poll_recv(&self, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_read_ready(ctx, mio::Ready::readable()))?;

        match self.io.get_ref().recv(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(ctx, mio::Ready::readable())?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;
    use tokio::time;

    #[tokio::test]
    async fn connect() {
        let mut s_buffer = [0u8; 1500];
        let mut r_buffer = [0u8; 1500];
        let mut packet = pppoe::Packet::new_discovery_packet(
            &mut s_buffer[..],
            &[0xfe, 0xb9, 0x04, 0x2a, 0xb2, 0x35],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        )
        .unwrap();

        let pppoe_header = packet.pppoe_header_mut();
        pppoe_header.add_tag(pppoe::Tag::PppMaxMtu(2000));
        pppoe_header.add_tag(pppoe::Tag::ServiceName(b"\0"));
        pppoe_header.add_tag(pppoe::Tag::RelaySessionId(b"abc"));
        pppoe_header.add_tag(pppoe::Tag::HostUniq(b"abcanretadi\0arnedt"));
        pppoe_header.add_vendor_tag_with_callback(|buffer| {
            let tr101 = pppoe::Tr101Information::with_both_ids("circuit", "remoteid")?;
            tr101.write(buffer)
        });
        pppoe_header.add_tag(pppoe::Tag::EndOfList);

        let sock = Socket::new("pppoe").unwrap();

        let len = loop {
            sock.send(&packet).await.unwrap();
            let recv = sock.recv(&mut r_buffer[..]);
            match time::timeout(Duration::from_secs(5), recv).await {
                Ok(result) => break result.unwrap(),
                _ => continue,
            }
        };

        let packet = pppoe::Packet::from_buffer(&mut r_buffer[..len]).unwrap();
    }
}
