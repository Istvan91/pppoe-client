use pppoe::error::Error;
use pppoe_client::{Configuration, Session};


#[tokio::main]
async fn main() {
    let config = Configuration {
        padi_retry: 1,
        padr_retry: 3,
        pado_timeout: std::time::Duration::from_secs(3),
        pads_timeout: std::time::Duration::from_secs(3),
        system_name: None,
        service_name: None,
        mtu: None,
        host_uniq: Some(b"n23fq98i\0\0ae90123n   4khtn21t\0\0".to_vec()),
    };

    let mut session = Session::new(config, "pppoe").unwrap();
    session.discover(|packet| {
        let address = packet.ethernet_header().src_address();
        let service = packet.pppoe_header().tags().find(|tag| tag.get_tag_type() ==  pppoe::tag::TAG_SERVICE_NAME).unwrap();
        println!("Service \"{}\" at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 service.get_message().unwrap().unwrap(),
                 address[0], address[1], address[2], address[3],address[4], address[5]
                );
        false
    }).await.map_err(|err| println!("{:?}", err)).ok();
}
