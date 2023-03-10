//! Based on: https://github.com/pekman/openvpn-netns

use std::process::Command;

use futures::stream::TryStreamExt;
use netns_rs::NetNs;

pub struct NetworkNamespace {
    pub name: String,
    netns: NetNs,
}

impl NetworkNamespace {
    pub fn new(name: &str) -> Result<Self, netns_rs::Error> {
        Ok(Self {
            name: name.to_string(),
            netns: NetNs::new(name)?,
        })
    }

    pub async fn add_loopback(&self) -> Result<(), rtnetlink::Error> {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let link = handle
            .link()
            .get()
            .match_name(String::from("lo"))
            .execute()
            .try_next()
            .await?
            .unwrap();

        handle.link().set(link.header.index).up().execute().await?;

        self.netns.run(|ns_| {
            Command::new("ip")
                .args(["link", "set", "dev", "lo", "up"])
                .status();
        });

        Ok(())
    }
}

/// When called the first time, create netns-specific
/// resolv.conf. 'ip netns exec' will bind mount this into
/// /etc/resolv.conf inside the namespace. (note: This is
/// compatible with NetworkManager, because it only cares about
/// the normal namespaceless resolv.conf.)
fn create_resolv_conf() {
    /* [ -n "$resolv_conf_created" ] && return
    resolv_conf_created=true

    # create directories and a temporary file that marks the
    # resolv.conf as ours so that we know we should delete it
    # and the directories afterwards
    if ! [ -e /etc/netns/"$NETNS" ]; then
        if ! [ -e /etc/netns ]; then
            mkdir /etc/netns
            echo netns/ns > "$TMPFILE_DIR"/created-resolvconf-"$NETNS"
        else
            echo ns > "$TMPFILE_DIR"/created-resolvconf-"$NETNS"
        fi
        mkdir /etc/netns/"$NETNS"
    else
        : > "$TMPFILE_DIR"/created-resolvconf-"$NETNS"
    fi

    # copy of $NETNS with control characters replaced with '?'
    SAFE_NETNS="$(printf '%s' "$NETNS" | tr '\0-\37\177' '[?*]')"
    printf '%s\n' \
        "# Generated for openvpn connection in network namespace \"$SAFE_NETNS\"." \
        "# This file will be automatically deleted." \
        "# (Created as /etc/netns/$SAFE_NETNS/resolv.conf. 'ip netns exec' will" \
        "# bind mount this into /etc/resolv.conf inside the namespace.)" \
        "" \
        > /etc/netns/"$NETNS"/resolv.conf
    # When changing the first line of the above, also change
    # the test string in the $script_type=down handler below. */
}

/// Process one OpenVPN foreign option. Called with unquoted
/// $foreign_option_<n>.
fn process_foreign_option() {
    /* case "$1:$2" in

        dhcp-option:DNS)
            # sanity check (IPv4 and IPv6 addresses allowed)
            case "$3" in
                *[!0-9a-fA-F.:]*) return ;;
            esac

            create_resolv_conf
            echo "nameserver $3" >> /etc/netns/"$NETNS"/resolv.conf
            ;;

        dhcp-option:DOMAIN)
            # sanity check (valid domain names allowed)
            case "$3" in
                *[!-0-9a-zA-Z.]*) return ;;
            esac

            create_resolv_conf
            foreign_opt_domains="$foreign_opt_domains $3"
            ;;
    esac */
}

/// Add domains to resolv.conf. Called with unquoted
/// $foreign_opt_domains.
fn add_domains_to_resolv_conf() {
    /* if [ $# -gt 0 ]; then
        # Not sure if multiple DOMAIN options is legal and if
        # this is the proper way to handle them. Use first
        # domain as our local domain and add all of them to
        # the domain search list.
        printf '%s\n' \
                "domain $1" \
                "search $*" \
                >> /etc/netns/"$NETNS"/resolv.conf
    fi */
}

pub fn on_ovpn_up() {
    // mkdir -p "$TMPFILE_DIR"

    let ns = netns_rs::NetNs::new("vpn").unwrap();

    // # create namespace if it doesn't exist yet
    // if ! [ -e "/var/run/netns/$NETNS" ]; then
    //     ip netns add "$NETNS"  || exit
    //     ip netns exec "$NETNS"  ip link set dev lo up
    ns.run(|ns_| {
        Command::new("ip")
            .args(["link", "set", "dev", "lo", "up"])
            .status();
    });
    //     # create temporary file that marks the namespace as ours
    //     # so that we know we should delete it afterwards
    //     : > "$TMPFILE_DIR"/created-netns-"$NETNS"
    // else
    //     # if namespace exists and there is a temporary file left
    //     # from some previous execution of this script, delete the
    //     # file
    //     rm -f "$TMPFILE_DIR"/created-netns-"$NETNS"
    // fi

    // # move TUN/TAP device to the network
    // ip link set  dev "$dev"  up  netns "$NETNS"  mtu "$tun_mtu"

    Command::new("ip")
        .args([
            "link", "set", "dev", dev, "up", "netns", netns, "mtu", tun_mtu,
        ])
        .status();

    // # set device address
    // netmask4="${ifconfig_netmask:-30}"
    // netbits6="${ifconfig_ipv6_netbits:-112}"
    // if [ -n "$ifconfig_local" ]; then
    //     if [ -n "$ifconfig_remote" ]; then
    //         ip netns exec "$NETNS" \
    //            ip -4 addr add \
    //                local "$ifconfig_local" \
    //                peer "$ifconfig_remote/$netmask4" \
    //                ${ifconfig_broadcast:+broadcast "$ifconfig_broadcast"} \
    //                dev "$dev"
    //     else
    //         ip netns exec "$NETNS" \
    //            ip -4 addr add \
    //                local "$ifconfig_local/$netmask4" \
    //                ${ifconfig_broadcast:+broadcast "$ifconfig_broadcast"} \
    //                dev "$dev"
    //     fi
    // fi
    // if [ -n "$IPV6" -a -n "$ifconfig_ipv6_local" ]; then
    //     if [ -n "$ifconfig_ipv6_remote" ]; then
    //         ip netns exec "$NETNS" \
    //            ip -6 addr add \
    //               local "$ifconfig_ipv6_local" \
    //               peer "$ifconfig_ipv6_remote/$netbits6" \
    //               dev "$dev"
    //     else
    //         ip netns exec "$NETNS" \
    //            ip -6 addr add \
    //               local "$ifconfig_ipv6_local/$netbits6" \
    //               dev "$dev"
    //     fi
    // fi

    // # if there already is a resolv.conf for our netns, don't
    // # overwrite it
    // if ! [ -e /etc/netns/"$NETNS"/resolv.conf ]; then
    //     # add DNS settings if given in foreign options
    //     i=1
    //     while
    //         eval opt=\"\$foreign_option_$i\"
    //         [ -n "$opt" ]
    //     do
    //         process_foreign_option $opt
    //         i=$(( i + 1 ))
    //     done
    //     add_domains_to_resolv_conf $foreign_opt_domains
    // fi
    // ;;
}

pub fn on_ovpn_route_up() {
    /* # set routes inside the namespace
            ip netns exec "$NETNS"  sh <<'EOF'
                i=1
                while
                    eval net=\"\$route_network_$i\"
                    eval mask=\"\$route_netmask_$i\"
                    eval gw=\"\$route_gateway_$i\"
                    eval mtr=\"\$route_metric_$i\"
                    [ -n "$net" ]
                do
                    ip -4 route add  "$net/$mask"  via "$gw"  ${mtr:+metric "$mtr"}
                    i=$(( i + 1 ))
                done

                if [ -n "$route_vpn_gateway" ]; then
                    ip -4 route add  default  via "$route_vpn_gateway"
                fi

                if [ -n "$IPV6" ]; then
                    i=1
                    while
                        # There doesn't seem to be $route_ipv6_metric_<n>
                        # according to the manpage.
                        eval net=\"\$route_ipv6_network_$i\"
                        eval gw=\"\$route_ipv6_gateway_$i\"
                        [ -n "$net" ]
                    do
                        ip -6 route add  "$net"  via "$gw"  metric 100
                        i=$(( i + 1 ))
                    done

                    # There's no $route_vpn_gateway for IPv6. It's not
                    # documented if OpenVPN includes default route in
                    # $route_ipv6_*. Set default route to remote VPN
                    # endpoint address if there is one. Use higher metric
                    # than $route_ipv6_* routes to give preference to a
                    # possible default route in them.
                    if [ -n "$ifconfig_ipv6_remote" ]; then
                        ip -6 route add  default \
                            via "$ifconfig_ipv6_remote"  metric 200
                    fi
                fi
    EOF
            ;; */
}

pub fn on_ovpn_down() {
    /* # if this script created the network namespace, clean up
    if [ -e "$TMPFILE_DIR"/created-netns-"$NETNS" ]; then
        rm "$TMPFILE_DIR"/created-netns-"$NETNS"
        ip netns del "$NETNS"
    fi

    # if this script created a netns-specific resolv.conf, clean up
    if [ -e "$TMPFILE_DIR"/created-resolvconf-"$NETNS" ]; then
        # double-check that it's ours
        case "$(head -n 1 /etc/netns/"$NETNS"/resolv.conf)" in
            '# Generated for openvpn connection in network namespace "'*)

                rm /etc/netns/"$NETNS"/resolv.conf

                # If we created the directories too, try to remove
                # them. Ignore errors silently, because someone
                # might have created other files there.
                case "$(cat "$TMPFILE_DIR"/created-resolvconf-"$NETNS")" in
                    ns)
                        rmdir /etc/netns/"$NETNS"  2>/dev/null
                        ;;
                    netns/ns)
                        rmdir /etc/netns/"$NETNS" /etc/netns  2>/dev/null
                        ;;
                esac
                ;;
        esac
        rm "$TMPFILE_DIR"/created-resolvconf-"$NETNS"
    fi
    ;; */
}
