use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, util::TryInitError, EnvFilter};

pub fn setup() -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::TRACE.into())
                .from_env_lossy(),
        )
        .try_init()
}
