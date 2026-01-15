//! CLI subcommand for the distributed tracing aggregator.

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use log::info;

use crate::cli::{MainConfig, SubCommandParserRunner};
use crate::core::distributed::{
    AggregatorConfig, ClickHouseConfig, ClickHouseEventSink, EventSink, LoggingEventSink,
    SharedBackpressure, TraceAggregator, DEFAULT_LISTEN_ADDR,
};
use crate::helpers::signals::Running;

/// Environment variable for ClickHouse password.
const CLICKHOUSE_PASSWORD_ENV: &str = "RETIS_CLICKHOUSE_PASSWORD";

#[derive(Parser, Debug, Default)]
#[command(
    name = "aggregate",
    about = "Run the distributed tracing aggregator.",
    long_about = "Run the distributed tracing aggregator.

The aggregator receives events from distributed collectors running on multiple nodes,
stores them in ClickHouse, and enables cross-node packet correlation.

Collectors connect using `retis collect --distributed --aggregator <addr>`.

Examples:
  retis aggregate
  retis aggregate --listen 0.0.0.0:9000
  retis aggregate --no-clickhouse"
)]
pub(crate) struct Aggregate {
    #[arg(
        long,
        default_value = DEFAULT_LISTEN_ADDR,
        help = "Address to listen for collector connections."
    )]
    listen: String,

    #[arg(
        long,
        default_value = "http://localhost:8123",
        help = "ClickHouse HTTP URL."
    )]
    clickhouse_url: String,

    #[arg(long, default_value = "retis", help = "ClickHouse database name.")]
    clickhouse_database: String,

    #[arg(long, default_value = "retis_events", help = "ClickHouse table name.")]
    clickhouse_table: String,

    #[arg(long, help = "ClickHouse username.")]
    clickhouse_user: Option<String>,

    #[arg(
        long,
        help = "Path to file containing ClickHouse password. Takes precedence over environment variable."
    )]
    clickhouse_password_file: Option<String>,

    #[arg(long, default_value = "100", help = "Maximum collector connections.")]
    max_connections: usize,

    #[arg(long, help = "Disable ClickHouse, log events instead (for testing).")]
    no_clickhouse: bool,
}

impl Aggregate {
    fn get_password(&self) -> Result<Option<String>> {
        // File takes precedence over environment variable.
        if let Some(path) = &self.clickhouse_password_file {
            let password = fs::read_to_string(path)
                .with_context(|| format!("reading password file {}", path))?
                .trim()
                .to_string();
            return Ok(Some(password));
        }

        if let Ok(password) = std::env::var(CLICKHOUSE_PASSWORD_ENV) {
            return Ok(Some(password));
        }

        Ok(None)
    }
}

impl SubCommandParserRunner for Aggregate {
    fn run(&mut self, _main_config: &MainConfig) -> Result<()> {
        let run = Running::new();
        run.register_term_signals()?;

        let backpressure = Arc::new(SharedBackpressure::new());

        let sink: Box<dyn EventSink> = if self.no_clickhouse {
            info!("Running in test mode (no ClickHouse storage)");
            Box::new(LoggingEventSink::new())
        } else {
            let password = self.get_password()?;
            let ch_config = ClickHouseConfig {
                url: self.clickhouse_url.clone(),
                database: self.clickhouse_database.clone(),
                table: self.clickhouse_table.clone(),
                user: self.clickhouse_user.clone(),
                ..Default::default()
            };

            info!(
                "Connecting to ClickHouse at {} (database: {}, table: {})",
                ch_config.url, ch_config.database, ch_config.table
            );

            Box::new(ClickHouseEventSink::new(
                ch_config,
                password.as_deref(),
                Arc::clone(&backpressure),
            )?)
        };

        let config = AggregatorConfig {
            listen_addr: self.listen.clone(),
            max_connections: self.max_connections,
            ..Default::default()
        };

        let mut aggregator = TraceAggregator::new(config, sink, backpressure, run.shutdown_flag())?;
        aggregator.run()
    }
}
