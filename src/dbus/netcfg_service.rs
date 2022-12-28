//! # DBus interface proxy for: `net.openvpn.v3.netcfg`
//!
//! This code was generated by `zbus-xmlgen` `3.1.0` from DBus introspection data.
//! Source: `net.openvpn.v3.netcfg.xml`.
//!
//! You may prefer to adapt it, instead of using it verbatim.
//!
//! More information can be found in the
//! [Writing a client proxy](https://dbus.pages.freedesktop.org/zbus/client.html)
//! section of the zbus documentation.
//!
//! This DBus object implements
//! [standard DBus interfaces](https://dbus.freedesktop.org/doc/dbus-specification.html),
//! (`org.freedesktop.DBus.*`) for which the following zbus proxies can be used:
//!
//! * [`zbus::fdo::PropertiesProxy`]
//! * [`zbus::fdo::IntrospectableProxy`]
//! * [`zbus::fdo::PeerProxy`]
//!
//! …consequently `zbus-xmlgen` did not generate code for the above interfaces.

use std::fmt;

use super::constants::{LogGroup, LogLevel};
use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;
use zbus::{dbus_proxy, zvariant::Type};

#[dbus_proxy(
    interface = "net.openvpn.v3.netcfg",
    default_service = "net.openvpn.v3.netcfg",
    default_path = "/net/openvpn/v3/netcfg"
)]
trait NetcfgService {
    /// Cleanup method
    fn cleanup(&self) -> zbus::Result<()>;

    /// CreateVirtualInterface method
    fn create_virtual_interface(
        &self,
        device_name: &str,
    ) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    /// DcoAvailable method
    fn dco_available(&self) -> zbus::Result<bool>;

    /// FetchInterfaceList method
    fn fetch_interface_list(&self) -> zbus::Result<Vec<zbus::zvariant::OwnedObjectPath>>;

    /// NotificationSubscribe method
    fn notification_subscribe(
        &self,
        filter: BitFlags<NetworkChangeEventFilterFlags>,
    ) -> zbus::Result<()>;

    /// NotificationSubscriberList method
    fn notification_subscriber_list(
        &self,
    ) -> zbus::Result<Vec<(String, NetworkChangeEventFilterFlags)>>;

    /// NotificationUnsubscribe method
    fn notification_unsubscribe(&self, optional_subscriber: &str) -> zbus::Result<()>;

    /// ProtectSocket method
    fn protect_socket(
        &self,
        remote: &str,
        ipv6: bool,
        device_path: &zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<bool>;

    /// Log signal
    #[dbus_proxy(signal)]
    fn log(&self, group: LogGroup, level: LogLevel, message: &str) -> zbus::Result<()>;

    /// config_file property
    #[dbus_proxy(property, name = "config_file")]
    fn config_file(&self) -> zbus::Result<String>;

    /// global_dns_search property
    #[dbus_proxy(property, name = "global_dns_search")]
    fn global_dns_search(&self) -> zbus::Result<u32>;

    /// global_dns_servers property
    #[dbus_proxy(property, name = "global_dns_servers")]
    fn global_dns_servers(&self) -> zbus::Result<u32>;

    /// log_level property
    #[dbus_proxy(property, name = "log_level")]
    fn log_level(&self) -> zbus::Result<u32>;
    fn set_log_level(&self, value: LogLevel) -> zbus::Result<()>;

    /// version property
    #[dbus_proxy(property, name = "version")]
    fn version(&self) -> zbus::Result<String>;
}

/// Flags used in the CheckAuthorization() method.
#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum NetworkChangeEventFilterFlags {
    ///	A new virtual interface has been added on the system
    DeviceAdded = 0x001,
    ///	A virtual interface has been removed from the system
    DeviceRemoved = 0x002,
    ///	An IP address has been added to a virtual interface
    IpaddrAdded = 0x004,
    ///	An IP address has been removed from the virtual interface
    IpaddrRemoved = 0x008,
    ///	A route has been added to the routing table, related to this interface
    RouteAdded = 0x010,
    ///	A route has been remove from the routing table, related to this interface
    RouteRemoved = 0x020,
    ///	A route has been excluded from the routing table, related to this interface
    RouteExcluded = 0x040,
    ///	A DNS server has been added to the DNS configuration
    DnsServerAdded = 0x080,
    ///	A DNS server has been removed from the DNS configuration
    DnsServerRemoved = 0x100,
    ///	A DNS search domain has been added to the DNS configuration
    DnsSearchAdded = 0x200,
    ///	A DNS search domain has been removed from the DNS configuration
    DnsSearchRemoved = 0x400,
}

assert_impl_all!(NetworkChangeEventFilterFlags: Send, Sync, Unpin);

impl fmt::Display for LogArgs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] ({}) - {}",
            self.level(),
            self.group(),
            self.message()
        )
    }
}