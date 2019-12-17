mod socket;

use socket::Socket;
use tokio::time;

use pppoe::error::Error;
use std::{self, io, num};

struct ClientConfiguration {
    padi_retry: u16,
    padr_retry: u16,
    pado_timeout: std::time::Duration,
    pads_timeout: std::time::Duration,
    system_name: Option<String>, // AC String
    service_name: Option<String>,
    mtu: Option<num::NonZeroU16>,
    host_uniq: Option<Vec<u8>>,
}


struct Session {
    socket: Socket,
    config: ClientConfiguration,
}


impl Session {
    pub fn new(config: ClientConfiguration, interface_name: &str) -> io::Result<Self> {
        Ok(Self {
            config,
            socket: Socket::new(interface_name)?,
        })
    }


    fn add_tags(&self, header: &mut pppoe::Header) -> Result<(), Error> {
        if let Some(mtu) = self.config.mtu {
            header.add_tag(pppoe::Tag::PppMaxMtu(u16::from(mtu)))?;
        }

        if let Some(host_uniq) = &self.config.host_uniq {
            header.add_tag(pppoe::Tag::HostUniq(&host_uniq));
        }

        header.add_tag(pppoe::Tag::EndOfList).map_err(Into::into)
    }


    fn create_padi(&self, packet: &mut pppoe::Packet) -> Result<(), Error> {
        let padi = packet.pppoe_header_mut();

        match &self.config.service_name {
            Some(service_name) => padi.add_tag(pppoe::Tag::ServiceName(service_name.as_bytes()))?,
            None => padi.add_tag(pppoe::Tag::ServiceName(b""))?,
        };

        self.add_tags(padi)
    }


    fn create_padr(&self, packet: &mut pppoe::Packet, pado: &pppoe::Packet) -> Result<(), Error> {
        let mut padr = pppoe::Header::create_padr_from_pado(
            packet.pppoe_header_mut().get_ref_mut(),
            pado.pppoe_header(),
            self.config.service_name.as_ref().map(|s| s.as_bytes()),
            self.config.system_name.as_ref().map(|s| s.as_bytes()),
        )?;

        self.add_tags(&mut padr)
    }


    async fn wait_for_packet<'a>(
        &self,
        packet: &pppoe::Packet<'_>,
        recv_buffer: &'a mut [u8],
        code: pppoe::Code,
    ) -> Result<usize, Error> {
        self.socket.send(packet).await;

        loop {
            let len = self.socket.recv(&mut recv_buffer[..]).await.unwrap();
            let received = pppoe::Packet::from_buffer(&mut recv_buffer[..len]);
            if let Ok(received) = &received {
                if self.packet_is_for_me(received) && received.pppoe_header().code() == code as u8 {
                    return Ok(len);
                }
            }
        }
    }


    pub async fn wait_for_packet_with_time_control<'a>(
        &self,
        packet: &pppoe::Packet<'_>,
        recv_buffer: &'a mut [u8],
        code: pppoe::Code,
        timeout: std::time::Duration,
        retries: u16,
    ) -> Result<pppoe::Packet<'a>, Error> {
        let counter = 0;

        let len = loop {
            if retries != 0 && counter >= retries {
                unimplemented!()
            };

            match time::timeout(timeout, self.wait_for_packet(packet, recv_buffer, code)).await {
                Ok(received) => break received.unwrap(),
                _timeout => (),
            }
            counter.wrapping_add(1);
        };
        pppoe::Packet::from_buffer(&mut recv_buffer[..len])
    }


    pub async fn wait_for_pado<'a>(
        &self,
        padi: &pppoe::Packet<'_>,
        recv_buffer: &'a mut [u8],
    ) -> Result<pppoe::Packet<'a>, Error> {
        let cfg = &self.config;
        self.wait_for_packet_with_time_control(
            padi,
            recv_buffer,
            pppoe::Code::Pado,
            cfg.pado_timeout,
            cfg.padi_retry,
        )
        .await
    }


    pub async fn wait_for_pads<'a>(
        &self,
        padr: &pppoe::Packet<'_>,
        recv_buffer: &'a mut [u8],
    ) -> Result<pppoe::Packet<'a>, Error> {
        let cfg = &self.config;
        self.wait_for_packet_with_time_control(
            padr,
            recv_buffer,
            pppoe::Code::Pads,
            cfg.pads_timeout,
            cfg.padr_retry,
        )
        .await
    }


    pub async fn connect(&self) -> u16 {
        let mut send_buffer = [0u8; 1500];
        let mut recv_buffer = [0u8; 1500];

        let mut packet = pppoe::Packet::new_discovery_packet(
            &mut send_buffer[..],
            &self.socket.mac_address(),
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        )
        .unwrap();

        loop {
            self.create_padi(&mut packet).unwrap();

            let pado = self.wait_for_pado(&packet, &mut recv_buffer).await.unwrap();

            packet
                .ethernet_header_mut()
                .set_dst_address(&pado.ethernet_header().src_address());
            self.create_padr(&mut packet, &pado).unwrap();

            match self.wait_for_pads(&packet, &mut recv_buffer).await {
                Ok(pads) => {
                    return pads.pppoe_header().session_id();
                }
                _ => continue,
            }
        }
    }


    fn packet_is_for_me(&self, received: &pppoe::Packet) -> bool {
        if received.ethernet_header().dst_address() != &self.socket.mac_address() {
            return false;
        }

        if let Some(host_uniq) = &self.config.host_uniq {
            for tag in received.pppoe_header().tag_iter() {
                if let pppoe::Tag::HostUniq(r_uniq) = tag {
                    return host_uniq == &r_uniq;
                }
            }
        }

        true
    }
}

#[tokio::main]
async fn main() {
    let config = ClientConfiguration {
        padi_retry: 0,
        padr_retry: 3,
        pado_timeout: std::time::Duration::from_secs(3),
        pads_timeout: std::time::Duration::from_secs(3),
        system_name: Some("bng".into()),
        service_name: None,
        mtu: None,
        host_uniq: Some(b"n23fq98i\0\0ae90123n   4khtn21t\0\0".to_vec()),
    };

    let session = Session::new(config, "pppoe").unwrap();
    println!("{}, session_id", session.connect().await);
}
