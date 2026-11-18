//! `connect --best` with periodic re-race and failover.

use crate::probe::{pick_best, race_profiles, should_switch, ProbeResult, RaceOptions};
use crate::tunnel::{
    clear_stop, connect, disconnect, is_connected, request_stop, stop_requested,
};
use ssc_core::{list_profiles, set_active, write_singbox_config_with_policy, Profile};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SIGINT_INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct BestConnectOptions {
    pub race: RaceOptions,
    /// How often to re-probe while connected.
    pub interval: Duration,
    /// Only switch to a faster node if gain ≥ this many ms.
    pub hysteresis_ms: u64,
    /// If true, return after first connect (no watch loop).
    pub once: bool,
}

impl Default for BestConnectOptions {
    fn default() -> Self {
        Self {
            race: RaceOptions::default(),
            interval: Duration::from_secs(45),
            hysteresis_ms: 40,
            once: false,
        }
    }
}

pub fn format_race_table(results: &[ProbeResult]) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<4} {:<8} {:>7}  {:<36} {}",
        "#", "status", "ms", "name", "endpoint"
    ));
    for (i, r) in results.iter().enumerate() {
        let status = if r.ok { "ok" } else { "fail" };
        let ms = r
            .latency_ms
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());
        let endpoint = if r.port == 0 {
            r.error.clone().unwrap_or_default()
        } else {
            format!("{}:{}", r.server, r.port)
        };
        let detail = if r.ok {
            endpoint
        } else {
            format!("{} ({})", endpoint, r.error.as_deref().unwrap_or("error"))
        };
        lines.push(format!(
            "{:<4} {:<8} {:>7}  {:<36} {}",
            i + 1,
            status,
            ms,
            truncate(&r.name, 36),
            detail
        ));
    }
    lines.join("\n")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn find_result<'a>(results: &'a [ProbeResult], profile_id: &str) -> Option<&'a ProbeResult> {
    results.iter().find(|r| r.profile_id == profile_id)
}

fn connect_profile(profile: &Profile) -> Result<(), String> {
    set_active(&profile.id)?;
    let policy = ssc_policy::load_policy().unwrap_or_default();
    let uri = ssc_core::profile_uri(profile)?;
    let config = write_singbox_config_with_policy(&uri, &policy)?;
    eprintln!(
        "connecting {} ({}) latency-selected",
        profile.name, profile.protocol
    );
    connect(&config, Some(&profile.id))?;
    Ok(())
}

fn profile_by_id(id: &str) -> Result<Profile, String> {
    let file = list_profiles()?;
    file.profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| format!("profile not found: {id}"))
}

/// One-shot race; returns sorted results. Optionally sets active to winner when `use_best`.
pub fn run_race(use_best: bool) -> Result<Vec<ProbeResult>, String> {
    let file = list_profiles()?;
    if file.profiles.is_empty() {
        return Err("no profiles — run `ssc add` first".into());
    }
    eprintln!("racing {} profiles…", file.profiles.len());
    let results = race_profiles(&file.profiles, &RaceOptions::default());
    if use_best {
        if let Some(best) = pick_best(&results) {
            set_active(&best.profile_id)?;
            eprintln!(
                "active={} ({} ms)",
                best.name,
                best.latency_ms.unwrap_or(0)
            );
        } else {
            return Err("no reachable profiles".into());
        }
    }
    Ok(results)
}

/// Connect to lowest-latency reachable profile; optionally watch and failover.
pub fn connect_best(opts: BestConnectOptions) -> Result<(), String> {
    let file = list_profiles()?;
    if file.profiles.is_empty() {
        return Err("no profiles — run `ssc add` first".into());
    }
    if is_connected() {
        return Err("already connected — run `ssc disconnect` first".into());
    }

    clear_stop()?;
    eprintln!("racing {} profiles…", file.profiles.len());
    let results = race_profiles(&file.profiles, &opts.race);
    eprintln!("{}", format_race_table(&results));
    let best = pick_best(&results).ok_or_else(|| "no reachable profiles".to_string())?;
    let mut current_id = best.profile_id.clone();
    connect_profile(&profile_by_id(&current_id)?)?;

    if opts.once {
        return Ok(());
    }

    eprintln!(
        "failover watch: interval={}s hysteresis={}ms (Ctrl+C or `ssc disconnect` to stop)",
        opts.interval.as_secs(),
        opts.hysteresis_ms
    );

    install_sigint_handler();

    loop {
        std::thread::sleep(opts.interval);
        if stop_requested() {
            eprintln!("stop requested");
            let _ = disconnect();
            clear_stop()?;
            break;
        }
        if !is_connected() {
            eprintln!("tunnel died — re-racing…");
            let results = race_profiles(&list_profiles()?.profiles, &opts.race);
            eprintln!("{}", format_race_table(&results));
            let Some(best) = pick_best(&results) else {
                eprintln!("no reachable profiles; retrying…");
                continue;
            };
            current_id = best.profile_id.clone();
            if let Err(e) = connect_profile(&profile_by_id(&current_id)?) {
                eprintln!("reconnect failed: {e}");
            }
            continue;
        }

        let results = race_profiles(&list_profiles()?.profiles, &opts.race);
        let current = find_result(&results, &current_id);
        let current_ok = current.map(|r| r.ok).unwrap_or(false);
        let current_ms = current.and_then(|r| r.latency_ms);
        let Some(best) = pick_best(&results) else {
            eprintln!("all probes failed; keeping current tunnel");
            continue;
        };

        if best.profile_id == current_id {
            continue;
        }

        if should_switch(
            current_ok,
            current_ms,
            best.ok,
            best.latency_ms,
            opts.hysteresis_ms,
        ) {
            eprintln!(
                "switching {} ({} ms) → {} ({} ms)",
                current.map(|c| c.name.as_str()).unwrap_or("?"),
                current_ms
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".into()),
                best.name,
                best.latency_ms.unwrap_or(0)
            );
            let _ = disconnect();
            std::thread::sleep(Duration::from_millis(400));
            if stop_requested() {
                clear_stop()?;
                break;
            }
            current_id = best.profile_id.clone();
            if let Err(e) = connect_profile(&profile_by_id(&current_id)?) {
                eprintln!("switch failed: {e}");
            }
        }
    }
    Ok(())
}

fn install_sigint_handler() {
    #[cfg(unix)]
    {
        if SIGINT_INSTALLED.swap(true, Ordering::SeqCst) {
            return;
        }
        unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_handler as *const () as libc::sighandler_t,
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &SIGINT_INSTALLED;
    }
}

#[cfg(unix)]
extern "C" fn sigint_handler(_: libc::c_int) {
    // Async-signal-safe enough for our stop AtomicBool + best-effort file write.
    let _ = request_stop();
}
