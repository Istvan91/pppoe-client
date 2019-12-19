use pppoe::error::Error;
use pppoe_client::{Configuration, Session};

use std::{self, io, num};
use tokio::time;

#[tokio::main]
async fn main() {
    let config = Configuration {
        padi_retry: 0,
        padr_retry: 3,
        pado_timeout: std::time::Duration::from_secs(3),
        pads_timeout: std::time::Duration::from_secs(3),
        system_name: Some("bng".into()),
        service_name: None,
        mtu: None,
        host_uniq: Some(b"n23fq98i\0\0ae90123n   4khtn21t\0\0".to_vec()),
    };

    let mut session = Session::new(config, "pppoe").unwrap();
    println!("{:?}, session_id", session.connect().await);
}
