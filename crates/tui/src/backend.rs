use anyhow::Result;
use async_trait::async_trait;

use crate::model::OpsSnapshot;

#[async_trait(?Send)]
pub trait OpsBackend {
    async fn load_snapshot(&mut self, selected_env: Option<&str>) -> Result<OpsSnapshot>;
    async fn destroy_env(&mut self, env: &str) -> Result<()>;
    async fn allow_approval(&mut self, request_id: &str) -> Result<()>;
    async fn deny_approval(&mut self, request_id: &str) -> Result<()>;
}
