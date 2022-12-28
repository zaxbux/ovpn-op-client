mod dbus;
//pub mod netns;

use clap::Parser;
use dbus::NetcfgServiceProxy;
use onepassword_cli::item;
use serde::Deserialize;
use std::{fs::File, io::BufReader, path::Path, thread::sleep, time::Duration};
use tokio::signal;
use zbus::{export::futures_util::StreamExt, Connection};

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
    let cli = Cli::parse();

    let profile = read_from_file("config.json", &cli.profile)?.ok_or(Error::ProfileNotFound)?;

    let op_cli = onepassword_cli::OpCLI::new().await?;
    op_cli.signin().run().await?;

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

    if let Some(ca) = get_item_file_content(&op_cli, &item, "ca.pem").await? {
        ovpn_config += &format!("\n<ca>\n{}</ca>", ca);
    }

    if let Some(cert) = get_item_file_content(&op_cli, &item, "client.pem").await? {
        ovpn_config += &format!("\n<cert>\n{}</cert>", cert);
    }

    if let Some(key) = get_item_file_content(&op_cli, &item, "client.key").await? {
        ovpn_config += &format!("\n<key>\n{}</key>", key);
    }

    if let Some(ta) = get_item_file_content(&op_cli, &item, "ta.key").await? {
        ovpn_config += &format!("\n<tls-auth>\n{}</tls-auth>", ta);
    }

    let connection = Connection::system().await?;

    let netcfg = NetcfgServiceProxy::new(&connection).await?;
    let mut netcfg_log_stream = netcfg.receive_log().await?;

    let session_manager = dbus::SessionsProxy::new(&connection).await?;

    let mut log_stream = session_manager.receive_log().await?;
    let mut event_stream = session_manager.receive_session_manager_event().await?;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(log) = netcfg_log_stream.next() => {
                    println!("[netcfg][log]{}", log.args().unwrap());
                },
                Some(log) = log_stream.next() => {
                    println!("[sessions][log]: {:?}", log.args().unwrap());
                },
                Some(event) = event_stream.next() => {
                    println!("[sessions][event]: {}", event.args().unwrap());
                },
                else => break
            }
        }
    });

    // This step imports a standard OpenVPN configuration file into the configuration manager.
    // The configuration file must include all external files embedded into the data being imported.
    let configuration_manager =
        dbus::configuration::ConfigurationManagerProxy::new(&connection).await?;

    let config = configuration_manager
        .import(&profile.name, &ovpn_config, true, true)
        .await?;

    // This D-Bus method call needs to provide the unique path to a configuration object, provided by the Import call in the previous step.
    // This call will return a unique object path to this particular VPN session.
    // If information from the user is required, the session manager will issue a AttentionRequired signal which describes what it requires.
    // It is the front-end application's responsibility to act upon these signals.
    let session = session_manager.new_tunnel(&config.path()).await?;

    let mut status_change_stream = session.receive_status_change().await?;
    let mut attention_required_stream = session.receive_attention_required().await?;
    let mut log_stream = session.receive_log().await?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(log) = log_stream.next() => {
                    let args = log.args().unwrap();
                    println!("[session][log]: {:?}", args);
                },
                Some(status_change) = status_change_stream.next() => {
                    println!("[session][status_change]: {:?}", status_change.args());
                },
                Some(attention_required) = attention_required_stream.next() => {
                    let args = attention_required.args().unwrap();
                    println!("[session][attention_required]: {:?}", args);
                },
                else => break
            }
        }
    });

    // This method call must be called to ensure the backend VPN process is ready to connect.
    // It will not return anything if it is ready to connect.
    // Otherwise it will return an exception with more details.
    let mut ready = false;
    while !ready {
        if let Err(err) = session.ready().await {
            let err_str = err.to_string();
            if err_str.find(" Missing user credentials").is_some() {
                let ui_type_group = session.user_input_queue_get_type_group().await?;

                for (type_, group) in ui_type_group {
                    let ui_queue_check = session.user_input_queue_check(type_, group).await?;

                    for id in ui_queue_check {
                        let (type_, group, id, name, _description, _hidden_input) =
                            session.user_input_queue_fetch(type_, group, id).await?;

                        if name == "username" {
                            session
                                .user_input_provide(type_, group, id, &username)
                                .await?;
                        }

                        if name == "password" {
                            session
                                .user_input_provide(type_, group, id, &password)
                                .await?;
                        }
                    }
                }
            } else if err_str.find("Backend VPN process is not ready").is_some() {
                sleep(Duration::from_secs(1));
            }
        } else {
            ready = true;
        }
    }

    session.log_forward(true).await?;

    session.connect().await?;

    /*let mut status = Status {
        major: dbus::constants::StatusMajor::UNSET,
        minor: dbus::constants::StatusMinor::UNSET,
        status_message: String::from(""),
    };

    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = async {
            loop {
                if let Ok(maybe_status) = session.status().await {
                    if maybe_status != status {
                        status = maybe_status;
                        println!("{:?}", status);
                    }
                }
            }
        } => {}
    }; */

    signal::ctrl_c().await?;

    for (label, value) in session.statistics().await? {
        println!("\t{}: {}", label, value);
    }

    session.disconnect().await?;

    Ok(())
}
