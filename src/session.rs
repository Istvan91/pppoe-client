use tokio::time;

use crate::{Configuration, Socket};
use pppoe::error::Error;
use std::{self, io, num, future};
use std::os::unix::io::RawFd;

pub struct Session {
    socket: Socket,
    config: Configuration,
}

impl Session {
    pub fn new(config: Configuration, interface_name: &str) -> io::Result<Self> {
        Ok(Self {
            config,
            socket: Socket::new(interface_name)?,
        })
    }

    fn add_tags(&self, header: &mut pppoe::HeaderBuilder) -> Result<(), Error> {
        if let Some(mtu) = self.config.mtu {
            header.add_tag(pppoe::Tag::PppMaxMtu(u16::from(mtu)))?;
        }

        if let Some(host_uniq) = &self.config.host_uniq {
            header.add_tag(pppoe::Tag::HostUniq(&host_uniq));
        }

        header.add_tag(pppoe::Tag::EndOfList).map_err(Into::into)
    }

    fn create_padi<'a>(&self, send_buffer: &'a mut [u8]) -> Result<pppoe::PacketBuilder<'a>, Error> {
        let mut packet = pppoe::PacketBuilder::new_discovery_packet(
            send_buffer,
            self.socket.mac_address(),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        )?;

        let padi = packet.pppoe_header();

        match &self.config.service_name {
            Some(service_name) => padi.add_tag(pppoe::Tag::ServiceName(service_name.as_bytes()))?,
            None => padi.add_tag(pppoe::Tag::ServiceName(b""))?,
        };

        self.add_tags(padi)?;

        Ok(packet)
    }

    fn create_padr(
        &self,
        packet: &mut pppoe::PacketBuilder,
        pado: &pppoe::Packet,
    ) -> Result<(), Error> {
        let mut padr = pppoe::HeaderBuilder::create_padr_from_pado(
            packet.pppoe_header().get_ref_mut(),
            pado.pppoe_header(),
            self.config.service_name.as_ref().map(|s| s.as_bytes()),
            self.config.system_name.as_ref().map(|s| s.as_bytes()),
        )?;

        self.add_tags(&mut padr)
    }

    async fn recv<'a>(&self, buffer: &'a mut [u8], code: pppoe::Code) -> Result<pppoe::Packet<'a>, Error> {

        let len = self.socket.recv(buffer).await?;
        
        let packet = pppoe::Packet::with_buffer(&buffer[..len])?;
        if self.packet_is_for_me(&packet) && packet.pppoe_header().code() == code as u8 {
            return Ok(packet);
        }
        unimplemented!()
    }


    async fn wait_for_packets<'a, F>(&self, code: pppoe::Code, send_buffer: &[u8], recv_buffer: &'a mut [u8], timeout: std::time::Duration, retries: u16, mut check_packet: F) -> Result<pppoe::Packet<'a>, Error>
        where F: FnMut(&pppoe::Packet) -> bool
    {
        let mut counter = 0;
        let len = 'outer: loop {
            if retries != 0 && counter == retries {
                unimplemented!() // return TimeoutError
            }

            self.socket.send(send_buffer).await?;

            let timeout = time::Instant::now() + timeout;
            loop {
                match time::timeout_at(timeout, self.recv(recv_buffer, code)).await {
                    Ok(packet) => {
                        if let Ok(packet) = packet {
                            if check_packet(&packet) { break 'outer packet.len() }
                        }
                    }
                    Err(_) => break,
                }
            }

            counter += 1;
        };

        pppoe::Packet::with_buffer(&recv_buffer[..len])
    }


    async fn discover_internal<'a, F>(&self, send_buffer: &mut [u8], recv_buffer: &'a mut [u8], check_packet: F) -> Result<pppoe::Packet<'a>, Error>
        where F: FnMut(&pppoe::Packet) -> bool
    {

        let packet = self.create_padi(send_buffer).unwrap();

        self.wait_for_packets(pppoe::Code::Pado, packet.as_bytes(), recv_buffer, self.config.pado_timeout, self.config.padi_retry, check_packet).await
    }


    pub async fn discover<'a, F>(&mut self, check_packet: F) -> Result<(), Error>
        where F: FnMut(&pppoe::Packet) -> bool
    {
        let recv_buffer = &mut [0u8; 1500][..];
        let send_buffer = &mut [0u8; 200][..];

        self.discover_internal(send_buffer, recv_buffer, check_packet).await
            .map(|_| ())
    }


    pub async fn connect(&mut self) -> Result<RawFd, Error> {
        let send_buffer = &mut [0u8; 1500][..];
        let recv_buffer = &mut [0u8; 1500][..];

        loop {
            let pado = self.discover_internal(
                send_buffer,
                recv_buffer,
                |packet| {

                    if let Some(ref expected_service_name) = self.config.service_name {
                        for tag in packet.pppoe_header().tags() {
                            if let pppoe::Tag::ServiceName(service_name) = tag {
                                if service_name == expected_service_name.as_bytes() {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }
                    true
                }
            ).await?;

            let mut packet = pppoe::PacketBuilder::new_discovery_packet(
                send_buffer,
                pado.ethernet_header().dst_address(),
                pado.ethernet_header().src_address(),
            )?;

            self.create_padr(&mut packet, &pado)?;

            // self.establish_session(&packet)
            let pads = self.wait_for_packets(pppoe::Code::Pads, send_buffer, recv_buffer, self.config.pads_timeout, self.config.padr_retry, |_| true).await;

            match pads {
                Ok(pads) => {
                    let session_id = pads.pppoe_header().session_id();
                    if session_id == 0 {  }

                    self.socket.close();

                    return self.socket.connect_session_id(
                        num::NonZeroU16::new(session_id).unwrap(),
                        pads.ethernet_header().src_address())
                        .map_err(Into::into);
                }
                _ => continue,
            }
        }
    }

    fn packet_is_for_me(&self, received: &pppoe::Packet) -> bool {
        if received.ethernet_header().dst_address() != self.socket.mac_address() {
            return false;
        }

        // Some additional checks
        let src = received.ethernet_header().src_address();
        if src[0] == 0x01 || src == [0xffu8; 6] {
            return false;
        }

        if let Some(host_uniq) = &self.config.host_uniq {
            for tag in received.pppoe_header().tags() {
                if let pppoe::Tag::HostUniq(r_uniq) = tag {
                    return host_uniq == &r_uniq;
                }
            }
        }

        true
    }
}
