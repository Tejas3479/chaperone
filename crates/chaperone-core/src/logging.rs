use std::fmt;
use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt as sub_fmt, EnvFilter};

/// Marker trait for sensitive data that should never be logged in raw form.
pub trait Sensitive {}

/// A wrapper type that redacts its inner value in `Debug` output.
pub struct Scrubbed<T>(pub T);

impl<T> Sensitive for Scrubbed<T> {}

impl<T> fmt::Debug for Scrubbed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SCRUBBED]")
    }
}

impl<T> Scrubbed<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Clone> Clone for Scrubbed<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Copy> Copy for Scrubbed<T> {}

impl<T: PartialEq> PartialEq for Scrubbed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T: Eq> Eq for Scrubbed<T> {}

impl<T: PartialOrd> PartialOrd for Scrubbed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<T: Ord> Ord for Scrubbed<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T: std::hash::Hash> std::hash::Hash for Scrubbed<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: zeroize::Zeroize> zeroize::Zeroize for Scrubbed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: serde::Serialize> serde::Serialize for Scrubbed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Scrubbed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Scrubbed)
    }
}

/// Initializes local-only structured logging.
/// Writes to a local rotating file at the specified log directory.
pub fn init_logging(
    log_dir: &Path,
) -> Result<WorkerGuard, Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "chaperone.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = sub_fmt::Subscriber::builder()
        .json()
        .with_writer(non_blocking)
        .with_env_filter(filter)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrubbed_debug_output() {
        let val: [u8; 32] = [42; 32];
        let scrubbed = Scrubbed(val);
        let debug_str = format!("{:?}", scrubbed);
        assert_eq!(debug_str, "[SCRUBBED]");
        // Make sure the raw bytes aren't in there
        assert!(!debug_str.contains("42"));
    }
}
