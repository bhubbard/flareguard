use crate::zone::models::ZoneAuditData;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

/// Trait abstracting the data source for Cloudflare zones
pub trait ZoneDataProvider: Send + Sync {
    fn fetch_all_zones<'a>(
        &'a self,
        zone_filter: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ZoneAuditData>>> + Send + 'a>>;
}
