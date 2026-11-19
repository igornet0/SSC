//! SSC — standalone VPN CLI (VLESS / VMess / Trojan via sing-box).

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "ssc", version, about = "SSC local VPN policy gateway")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Import a share URI (`vless://` / `vmess://` / `trojan://`)
    Add {
        /// Share URI
        #[arg(required_unless_present = "path", conflicts_with = "path")]
        uri: Option<String>,
        /// Import URIs from a file (one per line, `#` comments allowed)
        #[arg(long)]
        path: Option<PathBuf>,
        /// With `--path`: delete all existing profiles first
        #[arg(long, requires = "path")]
        replace: bool,
    },
    /// List saved profiles
    List,
    /// Set active profile by id or name
    Use { id: String },
    /// Remove a profile by id or name
    Remove { id: String },
    /// Probe all profiles; print ranked latency table
    Race {
        /// Set active profile to the fastest reachable
        #[arg(long)]
        use_best: bool,
        /// Connect timeout per profile (seconds)
        #[arg(long, default_value_t = 3)]
        timeout: u64,
    },
    /// TCP ping to profile server (active by default)
    Ping {
        /// Profile id/name (default: active)
        #[arg(long)]
        id: Option<String>,
        /// Number of probes
        #[arg(short = 'c', long, default_value_t = 4)]
        count: u32,
        /// Seconds between probes
        #[arg(long, default_value_t = 1)]
        interval: u64,
        /// Connect timeout seconds
        #[arg(long, default_value_t = 3)]
        timeout: u64,
    },
    /// Connect (sing-box TUN; passwordless after `ssc privileges install`)
    Connect {
        /// Profile id/name (default: active)
        #[arg(long)]
        id: Option<String>,
        /// Start this pre-configured independent instance instead of `default`
        #[arg(long)]
        instance: Option<String>,
        /// Connection mode: `tun` (system VPN) or `proxy` (local HTTP/SOCKS)
        #[arg(long)]
        mode: Option<String>,
        /// Local proxy port (with `--mode proxy`; default: allocate safely)
        #[arg(long)]
        proxy_port: Option<u16>,
        /// Pick lowest-latency reachable profile and keep failover watch
        #[arg(long)]
        best: bool,
        /// With `--best`: connect once and exit (no failover loop)
        #[arg(long)]
        once: bool,
        /// Failover re-probe interval seconds (default 45)
        #[arg(long, default_value_t = 45)]
        interval: u64,
        /// Only switch if candidate is faster by at least this many ms (default 40)
        #[arg(long, default_value_t = 40)]
        hysteresis: u64,
        /// Probe timeout seconds (default 3)
        #[arg(long, default_value_t = 3)]
        timeout: u64,
    },
    /// Disconnect tunnel (also stops `--best` watch)
    Disconnect,
    /// Reconnect using current profile + policy
    Reconnect,
    /// Show connection status
    Status,
    /// Start local Web UI + API on 127.0.0.1 (http://ssc.lan)
    Start {
        #[arg(long, default_value_t = ssc_api::DEFAULT_PORT)]
        port: u16,
    },
    /// Set routing mode: selective | full
    Mode { mode: String },
    /// Policy rules
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Safe recovery: disconnect + clear SSC tunnel state
    #[command(name = "reset-network")]
    ResetNetwork,
    /// Run diagnostics
    Diagnostics {
        /// Emit JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Probe how a destination would be routed
    Probe {
        /// Domain or IP
        dest: String,
        #[arg(long)]
        json: bool,
    },
    /// Download / locate sing-box
    Setup,
    /// Install `ssc` into PATH and prepare VPN runtime (sing-box)
    Install {
        /// Install directory for the binary (default: ~/.local/bin or LocalAppData\\Programs\\ssc)
        #[arg(long)]
        prefix: Option<PathBuf>,
        /// Prefer system-wide install (`/usr/local/bin` on Unix)
        #[arg(long)]
        system: bool,
        /// Only install the CLI binary; skip sing-box download
        #[arg(long)]
        skip_setup: bool,
    },
    /// Remove the installed `ssc` binary (keeps profiles / sing-box)
    Uninstall {
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(long)]
        system: bool,
    },
    /// Passwordless TUN privileges (`/etc/sudoers.d/ssc`) + `ssc.lan` hosts entry
    Privileges {
        #[command(subcommand)]
        action: Option<PrivilegesCmd>,
    },
    /// Independent, concurrently running VPN instances (TUN or Local Proxy)
    #[command(subcommand)]
    Instance(InstanceCmd),
    /// Internal: run sing-box as elevated worker (do not call manually)
    #[command(name = "__tunnel-worker", hide = true)]
    TunnelWorker {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        singbox: PathBuf,
        #[arg(long)]
        profile_id: Option<String>,
        #[arg(long)]
        instance_id: Option<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        proxy_port: Option<u16>,
        #[arg(long)]
        clash_port: Option<u16>,
    },
}

#[derive(Subcommand, Debug)]
enum InstanceCmd {
    /// Create an independent instance (does not start it)
    Add {
        /// Instance id (default: derived from name)
        #[arg(long)]
        id: Option<String>,
        /// Human-readable name
        #[arg(long)]
        name: Option<String>,
        /// Profile id/name (default: active profile at start)
        #[arg(long)]
        profile: Option<String>,
        /// `proxy` (default, no root) or `tun` (system VPN)
        #[arg(long, default_value = "proxy")]
        mode: String,
        /// Proxy inbound: mixed | http | socks
        #[arg(long, default_value = "mixed")]
        proxy_kind: String,
        /// Explicit local proxy port (default: allocated from policy range)
        #[arg(long)]
        port: Option<u16>,
        /// Explicit Clash/admin port (default: allocated)
        #[arg(long)]
        clash_port: Option<u16>,
        /// Start immediately after creating
        #[arg(long)]
        start: bool,
    },
    /// List instances and their state
    List,
    /// Show one instance
    Show { id: String },
    /// Start one instance (others are untouched)
    Start { id: String },
    /// Stop one instance (others keep running)
    Stop { id: String },
    /// Restart one instance
    Restart { id: String },
    /// Remove an instance definition and its runtime files
    Remove { id: String },
    /// Tail an instance log (redacted)
    Logs {
        id: String,
        #[arg(long, default_value_t = 16 * 1024)]
        max_bytes: usize,
    },
    /// Show or replace an instance's isolated policy
    Policy {
        id: String,
        /// Set routing mode: selective | full
        #[arg(long)]
        mode: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PrivilegesCmd {
    /// Show whether Connect can run without a password prompt
    Status,
    /// Install `/etc/sudoers.d/ssc` (requires root / sudo once)
    Install,
    /// Remove passwordless sudoers entry
    Remove,
}

#[derive(Subcommand, Debug)]
enum RulesCmd {
    /// List rules
    List,
    /// Add a rule: `ssc rules add domain google.com vpn`
    Add {
        kind: String,
        value: String,
        action: String,
    },
    /// Remove by id or match value
    Remove { id: String },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn ensure_singbox() -> Result<(), String> {
    let check = ssc_runtime::check_setup();
    if check.needs_setup {
        eprintln!("sing-box missing — running setup…");
        ssc_runtime::run_setup()?;
    }
    Ok(())
}

fn print_instance(v: &ssc_service::InstanceStatusView) {
    println!(
        "id={} state={} mode={} kind={} endpoint={} pid={}",
        v.id,
        v.state.as_str(),
        v.mode,
        v.proxy_kind,
        v.endpoint.as_deref().unwrap_or("-"),
        v.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
    );
    if let Some(err) = &v.last_error {
        eprintln!("last_error={err}");
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Add { uri, path, replace } => {
            if let Some(path) = path {
                let uris = ssc_core::read_uri_file(&path)?;
                let added = if replace {
                    ssc_core::replace_profiles(&uris)?
                } else {
                    uris.iter()
                        .map(|u| ssc_core::add_profile(u))
                        .collect::<Result<Vec<_>, _>>()?
                };
                for p in &added {
                    println!("added profile {} ({}) [{}]", p.name, p.protocol, p.id);
                }
                println!(
                    "{} {} profiles from {}",
                    if replace { "replaced with" } else { "imported" },
                    added.len(),
                    path.display()
                );
                if let Some(active) = ssc_core::list_profiles()?.active_id {
                    println!("active={active}");
                }
            } else if let Some(uri) = uri {
                let p = ssc_core::add_profile(&uri)?;
                println!("added profile {} ({}) [{}]", p.name, p.protocol, p.id);
                println!("active={}", p.id);
            }
        }
        Commands::List => {
            let file = ssc_core::list_profiles()?;
            if file.profiles.is_empty() {
                println!("(no profiles)");
                return Ok(());
            }
            for p in &file.profiles {
                let mark = if file.active_id.as_deref() == Some(p.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!(
                    "{mark} {}  {}  {}  {}",
                    p.id,
                    p.protocol,
                    p.name,
                    if p.server.is_empty() {
                        ssc_core::server_of(p)
                    } else {
                        p.server.clone()
                    }
                );
            }
        }
        Commands::Use { id } => {
            let p = ssc_core::set_active(&id)?;
            println!("active={} ({})", p.id, p.name);
        }
        Commands::Remove { id } => {
            ssc_core::remove_profile(&id)?;
            println!("removed {id}");
        }
        Commands::Race { use_best, timeout } => {
            let file = ssc_core::list_profiles()?;
            if file.profiles.is_empty() {
                return Err("no profiles — run `ssc add` first".into());
            }
            eprintln!("racing {} profiles…", file.profiles.len());
            let opts = ssc_runtime::RaceOptions {
                timeout: Duration::from_secs(timeout),
            };
            let results = ssc_runtime::race_profiles(&file.profiles, &opts);
            println!("{}", ssc_runtime::format_race_table(&results));
            if use_best {
                let best = ssc_runtime::pick_best(&results)
                    .ok_or_else(|| "no reachable profiles".to_string())?;
                ssc_core::set_active(&best.profile_id)?;
                println!("active={} ({} ms)", best.name, best.latency_ms.unwrap_or(0));
            } else if let Some(best) = ssc_runtime::pick_best(&results) {
                println!(
                    "winner={} ({} ms) — pass --use-best to set active",
                    best.name,
                    best.latency_ms.unwrap_or(0)
                );
            } else {
                return Err("no reachable profiles".into());
            }
        }
        Commands::Ping {
            id,
            count,
            interval,
            timeout,
        } => {
            let profile = if let Some(id) = id {
                let file = ssc_core::list_profiles()?;
                file.profiles
                    .iter()
                    .find(|p| p.id == id || p.name == id)
                    .cloned()
                    .ok_or_else(|| format!("profile not found: {id}"))?
            } else {
                ssc_core::active_profile()?
            };
            let uri = ssc_core::profile_uri(&profile)?;
            let parsed = ssc_core::parse_share_uri(&uri).map_err(|e| e.to_string())?;
            println!(
                "PING {} ({}) -> {}:{}",
                profile.name, profile.protocol, parsed.server, parsed.server_port
            );
            let stats = ssc_runtime::ping_profile(
                &profile,
                count,
                Duration::from_secs(timeout),
                Duration::from_secs(interval),
            )?;
            let loss = stats
                .sent
                .checked_sub(stats.received)
                .and_then(|d| d.checked_mul(100))
                .and_then(|n| n.checked_div(stats.sent))
                .unwrap_or(0);
            println!("--- {} ping statistics ---", stats.name);
            println!(
                "{} packets transmitted, {} received, {}% packet loss",
                stats.sent, stats.received, loss
            );
            if let (Some(min), Some(avg), Some(max)) =
                (stats.min_ms(), stats.avg_ms(), stats.max_ms())
            {
                println!("rtt min/avg/max = {min}/{avg}/{max} ms");
            }
            if stats.received == 0 {
                return Err(stats
                    .last_error
                    .unwrap_or_else(|| "all probes failed".into()));
            }
        }
        Commands::Connect {
            id,
            instance,
            mode,
            proxy_port,
            best,
            once,
            interval,
            hysteresis,
            timeout,
        } => {
            ensure_singbox()?;
            if best {
                if id.is_some() || instance.is_some() || mode.is_some() {
                    return Err("use --best alone (not with --id, --instance or --mode)".into());
                }
                let opts = ssc_runtime::BestConnectOptions {
                    race: ssc_runtime::RaceOptions {
                        timeout: Duration::from_secs(timeout),
                    },
                    interval: Duration::from_secs(interval),
                    hysteresis_ms: hysteresis,
                    once,
                };
                // Legacy best path still uses full-tunnel builder inside connect_best;
                // prefer VpnManager for policy-aware single connect.
                ssc_runtime::connect_best(opts)?;
                if once {
                    println!("{}", ssc_runtime::status_summary());
                }
            } else if let Some(instance) = instance {
                let manager = ssc_service::VpnManager::global().instances();
                let view = ssc_service::run_blocking(manager.start(&instance))?;
                print_instance(&view);
            } else {
                if let Some(id) = id {
                    ssc_core::set_active(&id)?;
                }
                let selected = match mode.as_deref() {
                    None | Some("tun") | Some("system") => None,
                    Some("proxy") | Some("local") => Some(ssc_service::InstanceMode::Proxy),
                    Some(other) => {
                        return Err(format!("invalid mode: {other} (tun|proxy)"));
                    }
                };
                let status = match selected {
                    Some(ssc_service::InstanceMode::Proxy) => {
                        ssc_service::VpnManager::global().connect_proxy(proxy_port)?
                    }
                    _ => ssc_service::VpnManager::global().connect()?,
                };
                println!(
                    "state={} mode={} server={} interface={} endpoint={}",
                    status.state.as_str(),
                    status.mode,
                    status.server.as_deref().unwrap_or("-"),
                    status.interface.as_deref().unwrap_or("-"),
                    if selected.is_some() {
                        proxy_port
                            .map(|p| format!("http://127.0.0.1:{p}"))
                            .unwrap_or_else(|| "allocated".into())
                    } else {
                        "-".into()
                    }
                );
            }
        }
        Commands::Disconnect => {
            let _ = ssc_service::VpnManager::global().disconnect();
        }
        Commands::Reconnect => {
            let status = ssc_service::VpnManager::global().reconnect()?;
            println!("state={}", status.state.as_str());
        }
        Commands::Status => {
            let check = ssc_runtime::check_setup();
            println!("platform={}", check.platform);
            println!(
                "singbox={}",
                check.singbox_path.as_deref().unwrap_or("missing")
            );
            let status = ssc_service::VpnManager::global().status();
            println!("state={}", status.state.as_str());
            println!("mode={}", status.mode);
            println!("server={}", status.server.as_deref().unwrap_or("-"));
            println!("interface={}", status.interface.as_deref().unwrap_or("-"));
            println!("profile={}", status.profile_name.as_deref().unwrap_or("-"));
            println!("bytes_sent={}", status.bytes_sent);
            println!("bytes_received={}", status.bytes_received);
            if let Some(e) = status.last_error {
                println!("last_error={e}");
            }
        }
        Commands::Start { port } => {
            let report = ssc_service::reconcile_on_startup();
            if report.tunnel_cleared || report.kill_switch_deactivated {
                eprintln!(
                    "reconciled: tunnel_cleared={} kill_switch_deactivated={}",
                    report.tunnel_cleared, report.kill_switch_deactivated
                );
            }
            ssc_api::serve_blocking(port)?;
        }
        Commands::Mode { mode } => {
            let m = ssc_policy::PolicyMode::parse(&mode)
                .ok_or_else(|| format!("invalid mode: {mode} (selective|full)"))?;
            ssc_policy::set_mode(m).map_err(|e| e.to_string())?;
            println!("mode={}", m.as_str());
            let _ = ssc_service::VpnManager::global().apply_policy();
        }
        Commands::Rules(cmd) => match cmd {
            RulesCmd::List => {
                let snap = ssc_policy::load_policy().map_err(|e| e.to_string())?;
                if snap.rules.is_empty() {
                    println!("(no rules)");
                }
                for r in &snap.rules {
                    let en = if r.enabled { "on" } else { "off" };
                    println!(
                        "{}  {}  {}  {}  [{en}]",
                        r.id,
                        r.kind.as_str(),
                        r.value,
                        r.action.as_str()
                    );
                }
            }
            RulesCmd::Add {
                kind,
                value,
                action,
            } => {
                let k = ssc_policy::MatchKind::parse(&kind)
                    .ok_or_else(|| format!("invalid kind: {kind}"))?;
                let a = ssc_policy::Action::parse(&action)
                    .ok_or_else(|| format!("invalid action: {action}"))?;
                let rule = ssc_policy::add_rule(k, &value, a).map_err(|e| e.to_string())?;
                println!(
                    "added {} {} → {}",
                    rule.kind.as_str(),
                    rule.value,
                    rule.action.as_str()
                );
                let _ = ssc_service::VpnManager::global().apply_policy();
            }
            RulesCmd::Remove { id } => {
                ssc_policy::delete_rule(&id).map_err(|e| e.to_string())?;
                println!("removed {id}");
                let _ = ssc_service::VpnManager::global().apply_policy();
            }
        },
        Commands::ResetNetwork => {
            ssc_service::reset_network()?;
            println!("network reset complete");
        }
        Commands::Diagnostics { json } => {
            let report = ssc_service::run_diagnostics();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!("{}", ssc_service::format_diagnostics_pretty(&report));
            }
        }
        Commands::Probe { dest, json } => {
            let result = ssc_service::probe_destination(&dest);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            } else {
                println!("destination={}", result.destination);
                println!("action={}", result.action);
                println!("mode={}", result.policy_mode);
                println!("interface={}", result.interface.as_deref().unwrap_or("-"));
                println!("ips={}", result.resolved_ips.join(","));
                if let Some(r) = &result.matched_rule {
                    println!("matched={} {} {} → {}", r.id, r.kind, r.value, r.action);
                } else {
                    println!("matched=(default)");
                }
                println!("explanation={}", result.explanation);
            }
        }
        Commands::Setup => {
            let path = ssc_runtime::run_setup()?;
            println!("sing-box ready: {}", path.display());
            println!("version pin: {}", ssc_runtime::SINGBOX_VERSION);
        }
        Commands::Install {
            prefix,
            system,
            skip_setup,
        } => {
            let result = ssc_runtime::install(ssc_runtime::InstallOptions {
                prefix_bin: prefix,
                skip_setup,
                system,
            })?;
            ssc_runtime::print_usage_hint(&result);
            // System install as root → also grant passwordless TUN.
            if system && result.binary_path.to_string_lossy() == ssc_runtime::SYSTEM_SSC_BIN {
                match ssc_runtime::install_privileges() {
                    Ok(p) => println!("privileges: {}", p.display()),
                    Err(e) => eprintln!(
                        "privileges not installed ({e}). Later: sudo ssc privileges install"
                    ),
                }
            }
        }
        Commands::Uninstall { prefix, system } => {
            let path = ssc_runtime::uninstall(ssc_runtime::InstallOptions {
                prefix_bin: prefix,
                skip_setup: true,
                system,
            })?;
            println!("uninstalled {}", path.display());
        }
        Commands::Privileges { action } => {
            let action = action.unwrap_or(PrivilegesCmd::Status);
            match action {
                PrivilegesCmd::Status => {
                    println!("{}", ssc_runtime::privileges_status());
                    println!("passwordless={}", ssc_runtime::passwordless_tunnel_ok());
                }
                PrivilegesCmd::Install => {
                    let path = ssc_runtime::install_privileges()?;
                    println!("ok {}", path.display());
                }
                PrivilegesCmd::Remove => {
                    ssc_runtime::remove_privileges()?;
                    println!("ok removed");
                }
            }
        }
        Commands::Instance(cmd) => {
            let manager = ssc_service::VpnManager::global().instances();
            match cmd {
                InstanceCmd::Add {
                    id,
                    name,
                    profile,
                    mode,
                    proxy_kind,
                    port,
                    clash_port,
                    start,
                } => {
                    let req = ssc_service::CreateInstanceRequest {
                        id,
                        name,
                        profile_id: profile,
                        mode: Some(mode),
                        proxy_kind: Some(proxy_kind),
                        listen_port: port,
                        clash_api_port: clash_port,
                        start_on_boot: None,
                        ..Default::default()
                    };
                    let view = ssc_service::run_blocking(manager.create(req))?;
                    print_instance(&view);
                    if start {
                        let view = ssc_service::run_blocking(manager.start(&view.id))?;
                        print_instance(&view);
                    }
                }
                InstanceCmd::List => {
                    let views = ssc_service::run_blocking(manager.list())?;
                    if views.is_empty() {
                        println!("(no instances)");
                    }
                    for v in views {
                        println!(
                            "{:<20} {:<13} {:<7} {:<6} {}",
                            v.id,
                            v.state.as_str(),
                            v.mode,
                            v.proxy_kind,
                            v.endpoint.as_deref().unwrap_or("-")
                        );
                    }
                }
                InstanceCmd::Show { id } => {
                    let view = ssc_service::run_blocking(manager.status(&id))?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&view).unwrap_or_default()
                    );
                }
                InstanceCmd::Start { id } => {
                    let view = ssc_service::run_blocking(manager.start(&id))?;
                    print_instance(&view);
                }
                InstanceCmd::Stop { id } => {
                    let view = ssc_service::run_blocking(manager.stop(&id))?;
                    print_instance(&view);
                }
                InstanceCmd::Restart { id } => {
                    let view = ssc_service::run_blocking(manager.restart(&id))?;
                    print_instance(&view);
                }
                InstanceCmd::Remove { id } => {
                    ssc_service::run_blocking(manager.remove(&id))?;
                    println!("removed {id}");
                }
                InstanceCmd::Logs { id, max_bytes } => {
                    let text = ssc_service::run_blocking(manager.log_tail(&id, max_bytes))?;
                    print!("{text}");
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
                InstanceCmd::Policy { id, mode } => match mode {
                    Some(mode) => {
                        let parsed = ssc_policy::PolicyMode::parse(&mode)
                            .ok_or_else(|| format!("invalid mode: {mode} (selective|full)"))?;
                        let mut policy = ssc_service::run_blocking(manager.policy(&id))?;
                        policy.settings.mode = parsed;
                        let view = ssc_service::run_blocking(manager.set_policy(&id, &policy))?;
                        println!("instance={id} mode={}", view.policy_mode);
                    }
                    None => {
                        let policy = ssc_service::run_blocking(manager.policy(&id))?;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&policy).unwrap_or_default()
                        );
                    }
                },
            }
        }
        Commands::TunnelWorker {
            config,
            singbox,
            profile_id,
            instance_id,
            mode,
            proxy_port,
            clash_port,
        } => {
            let mode = match mode.as_deref() {
                Some(m) => Some(
                    ssc_service::InstanceMode::parse(m)
                        .ok_or_else(|| format!("invalid worker mode: {m}"))?,
                ),
                None => None,
            };
            ssc_runtime::run_instance_worker(
                &config,
                &singbox,
                profile_id.as_deref(),
                instance_id.as_deref(),
                mode,
                proxy_port,
                clash_port,
            )?;
        }
    }
    Ok(())
}
