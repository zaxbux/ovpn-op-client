//pub mod netns;

mod logging;

use clap::Parser;
use onepassword_cli::item;
use openvpn3_rs::OpenVPN3;
use serde::Deserialize;
use std::{fs::File, io::BufReader, path::Path, thread::sleep, time::Duration};
use tokio::signal;
use tracing::info;

use zbus::export::ordered_stream::OrderedStreamExt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// VPN Profile
    profile: String,
}

#[derive(Debug)]
pub enum Error {
    ProfileNotFound,
    ConfigFieldMissing,
    UsernamePasswordMissing,
    IOError(std::io::Error),
    OPError(onepassword_cli::error::Error),
    JSONError(serde_json::Error),
    DBusError(zbus::Error),
    OpenVPN3(openvpn3_rs::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(err)
    }
}

impl From<onepassword_cli::error::Error> for Error {
    fn from(err: onepassword_cli::error::Error) -> Self {
        Self::OPError(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::JSONError(err)
    }
}

impl From<zbus::Error> for Error {
    fn from(err: zbus::Error) -> Self {
        Self::DBusError(err)
    }
}

impl From<openvpn3_rs::Error> for Error {
    fn from(err: openvpn3_rs::Error) -> Self {
        Self::OpenVPN3(err)
    }
}

#[derive(Deserialize, Debug, Clone)]
struct Profile {
    name: String,
    //vault: String,
    item: String,
    //open: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    profiles: Vec<Profile>,
}

async fn get_item_file_content(
    op_cli: &onepassword_cli::OpCLI,
    item: &item::output::Item,
    name: &str,
) -> Result<Option<String>> {
    if let Some(file) = item.file_by_name(name) {
        if let Some(content) = op_cli.read(file.into()).run().await? {
            Ok(Some(content))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

fn read_from_file<P: AsRef<Path>>(path: P, name: &str) -> Result<Option<Profile>> {
    // Open the file in read-only mode with buffer.
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // Read the JSON contents of the file
    let config: Config = serde_json::from_reader(reader)?;

    Ok(config
        .profiles
        .iter()
        .find(|profile| profile.name == name)
        .cloned())
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup().expect("Error setting up logging");

    let cli = Cli::parse();

    let profile = read_from_file("config.json", &cli.profile)?.ok_or(Error::ProfileNotFound)?;

    info!("Loaded profile");

    let op_cli = onepassword_cli::OpCLI::new().await?;
    op_cli.signin().run().await?;

    info!("Signed in to 1Password");

    let item = op_cli.item().get(&profile.item).run().await?.unwrap();

    let (username, password) = if let (Some(username), Some(password)) = (
        item.field_by_id("username").and_then(|field| field.value),
        item.field_by_id("password").and_then(|field| field.value),
    ) {
        (username, password)
    } else {
        return Err(Error::UsernamePasswordMissing);
    };

    let mut ovpn_config = item
        .field_by_label("config")
        .and_then(|field| field.value)
        .ok_or(Error::ConfigFieldMissing)?;

    info!("Found VPN config");

    if let Some(ca) = get_item_file_content(&op_cli, &item, "ca.pem").await? {
        ovpn_config += &format!("\n<ca>\n{}</ca>", ca);
        info!("Found ca certificate");
    }

    if let Some(cert) = get_item_file_content(&op_cli, &item, "client.pem").await? {
        ovpn_config += &format!("\n<cert>\n{}</cert>", cert);
        info!("Found client certificate");
    }

    if let Some(key) = get_item_file_content(&op_cli, &item, "client.key").await? {
        ovpn_config += &format!("\n<key>\n{}</key>", key);
        info!("Found client key");
    }

    if let Some(ta) = get_item_file_content(&op_cli, &item, "ta.key").await? {
        ovpn_config += &format!("\n<tls-auth>\n{}</tls-auth>", ta);
        info!("Found tls-auth key");
    }

    let openvpn3 = OpenVPN3::connect().await?;

    info!("Connected to OpenVPN3 D-Bus");

    let netcfg = openvpn3.net_cfg_manager().await?;
    let mut netcfg_log_stream = netcfg.receive_log().await?;
    let mut log_stream = openvpn3.log_stream().await?;
    let mut event_stream = openvpn3.event_stream().await?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(log) = netcfg_log_stream.next() => {
                    info!("netcfg:log:{:?}", log.args());
                },
                Some(log) = log_stream.next() => {
                    info!("sessions:log:{:?}", log.args());
                },
                Some(event) = event_stream.next() => {
                    info!("sessions:event:{:?}", event.args());
                },
                else => break
            }
        }
    });

    let config = openvpn3
        .import(&profile.name, &ovpn_config, true, true)
        .await?;
    let session = config.new_tunnel().await?;

    let mut status_change_stream = session.status_change_stream().await?;
    let mut attention_required_stream = session.attention_required_stream().await?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(status_change) = status_change_stream.next() => {
                    info!("session:status_change:{:?}", status_change.args());
                },
                Some(attention_required) = attention_required_stream.next() => {
                    let args = attention_required.args().unwrap();
                    info!("session:attention_required:{:?}", args);
                },
                else => break
            }
        }
    });

    let mut ready = false;
    while !ready {
        if let Err(err) = session.ready().await {
            if err == openvpn3_rs::Error::MissingUserCredentials {
                for ui in session.fetch_user_input_slots().await? {
                    let var_name = ui.variable_name();
                    if var_name == "username" {
                        ui.provide_input(&username).await?;
                    }
                    if var_name == "password" {
                        ui.provide_input(&password).await?;
                    }
                }
            } else if err == openvpn3_rs::Error::BackendNotReady {
                sleep(Duration::from_secs(1));
            }
        } else {
            ready = true;
        }
    }

    let mut log_stream = session.log_stream().await?;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(log) = log_stream.next() => {
                    //let args = log.args().unwrap();
                    info!("session:status_change:{:?}", log.args());
                    //println!("[session][log]: {:?}", args);
                },
                else => break
            }
        }
    });

    info!("Connecting...");

    session.connect().await?;

    info!("Connected");

    signal::ctrl_c().await?;

    info!("Disconnecting...");

    for (label, value) in session.statistics().await? {
        println!("\t{}: {}", label, value);
    }

    session.disconnect().await?;

    info!("Disconnected");

    Ok(())
}
