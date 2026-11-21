mod cli;
mod client;
mod daemon;
mod model;
mod proto;
mod rules;
mod tui;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "tattle",
    version,
    about = "Tattle — an application firewall that tells you who's phoning home",
    long_about = "Tattle watches every new network connection on this machine, asks you about the ones \
                  no rule covers, and remembers your answers.\n\nRun without arguments for the interactive monitor."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the firewall daemon (as root; normally started by systemd)
    Daemon {
        #[arg(long, default_value = "/var/lib/tattle")]
        state_dir: std::path::PathBuf,
        #[arg(long, default_value = proto::SOCKET_PATH)]
        socket: String,
        /// Members of this group may control tattle
        #[arg(long, default_value = "wheel")]
        group: String,
        #[arg(long, default_value_t = 4200)]
        queue: u16,
        #[arg(long, default_value_t = 4201)]
        dns_queue: u16,
        /// Filter loopback traffic too (for testing in a network namespace)
        #[arg(long, hide = true)]
        include_loopback: bool,
    },
    /// Open the interactive monitor (default)
    Ui,
    /// Show daemon status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Set what happens to connections no rule covers
    Mode {
        /// alert | silent-allow | silent-deny
        mode: String,
    },
    /// Turn filtering on
    On,
    /// Turn filtering off (everything is allowed, still logged)
    Off,
    /// List rules
    Rules {
        #[arg(long)]
        json: bool,
    },
    /// Add an allow rule
    Allow(cli::RuleArgs),
    /// Add a deny rule
    Deny(cli::RuleArgs),
    /// Delete rules by id
    Rm { ids: Vec<u64> },
    /// Enable a rule
    Enable { id: u64 },
    /// Disable a rule
    Disable { id: u64 },
    /// Show or switch profile (use "none" for no profile)
    Profile { name: Option<String> },
    /// Manage blocklists
    Blocklist {
        #[command(subcommand)]
        cmd: cli::BlocklistCmd,
    },
    /// Show recent connections; -f to follow live
    Log {
        #[arg(short, long)]
        follow: bool,
        #[arg(short = 'n', long, default_value_t = 40)]
        lines: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show per-app traffic
    Apps {
        #[arg(long)]
        json: bool,
    },
    /// Print your rules as JSON
    Export,
    /// Add rules from a JSON file produced by `export`
    Import { file: std::path::PathBuf },
}

fn main() {
    let cli = Cli::parse();
    if !matches!(cli.cmd, Some(Cmd::Daemon { .. })) {
        // Behave like a normal CLI under `| head`. The daemon keeps Rust's
        // default (ignored), so a client hanging up can never kill it.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let result = match cli.cmd {
        None | Some(Cmd::Ui) => tui::run(),
        Some(Cmd::Daemon {
            state_dir,
            socket,
            group,
            queue,
            dns_queue,
            include_loopback,
        }) => daemon::run(daemon::DaemonArgs {
            state_dir,
            socket,
            group,
            conn_queue: queue,
            dns_queue,
            include_loopback,
        }),
        Some(Cmd::Status { json }) => cli::status(json),
        Some(Cmd::Mode { mode }) => cli::mode(&mode),
        Some(Cmd::On) => cli::enabled(true),
        Some(Cmd::Off) => cli::enabled(false),
        Some(Cmd::Rules { json }) => cli::rules(json),
        Some(Cmd::Allow(a)) => cli::add_rule(model::Action::Allow, a),
        Some(Cmd::Deny(a)) => cli::add_rule(model::Action::Deny, a),
        Some(Cmd::Rm { ids }) => cli::remove(ids),
        Some(Cmd::Enable { id }) => cli::set_enabled(id, true),
        Some(Cmd::Disable { id }) => cli::set_enabled(id, false),
        Some(Cmd::Profile { name }) => cli::profile(name),
        Some(Cmd::Blocklist { cmd }) => cli::blocklist(cmd),
        Some(Cmd::Log {
            follow,
            lines,
            json,
        }) => cli::log(follow, lines, json),
        Some(Cmd::Apps { json }) => cli::apps(json),
        Some(Cmd::Export) => cli::export(),
        Some(Cmd::Import { file }) => cli::import(&file),
    };
    if let Err(e) = result {
        eprintln!("tattle: {e:#}");
        std::process::exit(1);
    }
}
