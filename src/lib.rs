mod socket;
pub use socket::Socket;

mod session;
pub use session::Session;

use std::num::NonZeroU16;
use std::time::Duration;

#[derive(Default)]
pub struct Configuration {
    pub padi_retry: u16,
    pub padr_retry: u16,
    pub pado_timeout: Duration,
    pub pads_timeout: Duration,
    pub system_name: Option<String>, // AC String
    pub service_name: Option<String>,
    pub mtu: Option<NonZeroU16>,
    pub host_uniq: Option<Vec<u8>>,
}
