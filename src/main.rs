use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
};

use actix_web::{App, HttpServer};
use anyhow::Context;
use clap::Parser;
use simple_logger::SimpleLogger;

mod config;
mod route;

#[derive(clap::Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long, help = "Path of config file")]
    config: String,
    #[arg(long, default_value_t = false, help = "enable verbose")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::try_parse()?;

    init_logger(args.verbose)?;
    let config = config::Config::try_from(Path::new(&args.config))?;

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    let listener =
        TcpListener::bind(listen_addr).context(format!("Failed to bind at {:?}", listen_addr))?;

    HttpServer::new(move || App::new().configure(route::config))
        .listen(listener)?
        .run()
        .await?;

    Ok(())
}

fn init_logger(verbose: bool) -> anyhow::Result<()> {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    SimpleLogger::new().with_level(log_level).init()?;

    Ok(())
}
