mod route_ops;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vpn-helper", about = "Privileged VPN operations helper")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AddRoute {
        network: String,
        netmask: String,
        gateway: String,
    },
    DelRoute {
        network: String,
        netmask: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::AddRoute {
            network,
            netmask,
            gateway,
        } => route_ops::add_route(&network, &netmask, &gateway),
        Commands::DelRoute { network, netmask } => route_ops::del_route(&network, &netmask),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
