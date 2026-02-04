//! CLI subcommand for the distributed tracing aggregator.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::info;

use crate::cli::{MainConfig, SubCommandParserRunner};
use crate::core::distributed::{
    AggregatorConfig, DuckDbConfig, DuckDbEventSink, EventSink, LoggingEventSink, TraceAggregator,
};
use crate::helpers::signals::Running;

#[derive(Parser, Debug, Default)]
#[command(
    name = "aggregate",
    about = "Run the distributed tracing aggregator.",
    long_about = "Run the distributed tracing aggregator.

The aggregator receives events from distributed collectors running on multiple nodes,
stores them in a local DuckDB database, and enables cross-node packet correlation.

Collectors connect using `retis collect --distributed --aggregator <addr>`.

Examples:
  retis aggregate
  retis aggregate --listen 0.0.0.0:9000
  retis aggregate --db-file /tmp/retis-debug.duckdb
  retis aggregate --no-storage"
)]
pub(crate) struct Aggregate {
    #[arg(long, help = "Address to listen for collector connections.")]
    listen: Option<String>,

    #[arg(
        long,
        help = "Path to the DuckDB database file.",
        default_value = "./retis.duckdb"
    )]
    db_file: PathBuf,

    #[arg(long, help = "Maximum collector connections.")]
    max_connections: Option<usize>,

    #[arg(long, help = "Disable storage, log events instead (for testing).")]
    no_storage: bool,
}

impl SubCommandParserRunner for Aggregate {
    fn run(&mut self, _main_config: &MainConfig) -> Result<()> {
        let run = Running::new();
        run.register_term_signals()?;

        let sink: Box<dyn EventSink> = if self.no_storage {
            info!("Running in test mode (no storage)");
            Box::new(LoggingEventSink::new())
        } else {
            let db_config = DuckDbConfig::new(&self.db_file);

            info!("Using DuckDB database at {:?}", self.db_file);

            Box::new(DuckDbEventSink::new(db_config)?)
        };

        let config = AggregatorConfig {
            listen_addr: self
                .listen
                .clone()
                .unwrap_or_else(|| AggregatorConfig::default().listen_addr),
            max_connections: self
                .max_connections
                .unwrap_or_else(|| AggregatorConfig::default().max_connections),
            ..Default::default()
        };

        let mut aggregator = TraceAggregator::new(config, sink, run.shutdown_flag())?;
        aggregator.run()
    }
}
