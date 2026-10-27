//! Reactive scaffolding for applications built on `rust-api`.
//!
//! This module is business-logic free. It gives an application a place to
//! attach `oxkv` hooks and to run background systems. Domain logic lives in
//! the application crate, not in this one.
//!
//! `oxkv` hooks are read-only. Observers run on the writer path. Watchers
//! are bounded and lossy. This module documents those limits; it does not
//! hide them.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::{
    fs::{FsEngine, s3::S3ClientConfig},
    policy::PolicyEngine,
    sync::wal::Wal,
};

/// Read-only handle to the shared runtime. Clone freely.
#[derive(Clone)]
pub struct ReactiveContext {
    /// Policy engine (RBAC). Read-only use from reactive code.
    pub policy: Arc<PolicyEngine>,
    /// File storage engine.
    pub fs: Arc<FsEngine>,
    /// Durable change feed (WAL).
    pub wal: Arc<Wal>,
    /// Root database prefix, for building additional stores.
    pub db_prefix: String,
    /// S3 client configuration, for building additional stores.
    pub s3: S3ClientConfig,
    /// Cancellation token. Fires on shutdown.
    pub cancel: CancellationToken,
}

/// A background service that reacts to store changes.
#[async_trait]
pub trait ReactiveService: Send + Sync {
    /// Stable name for logs and metrics.
    fn name(&self) -> &'static str;

    /// Attach observers or validators to stores.
    ///
    /// Called once, before serving. Keep this method cheap and
    /// synchronous: it must not block on S3.
    fn register(&self, ctx: &ReactiveContext);

    /// Run until `ctx.cancel` fires. An error stops only this service.
    async fn run(&self, ctx: ReactiveContext) -> anyhow::Result<()>;
}

/// Register and spawn every service. Returns handles to await on shutdown.
pub fn spawn_services(
    services: &[Arc<dyn ReactiveService>],
    ctx: ReactiveContext,
) -> Vec<tokio::task::JoinHandle<anyhow::Result<()>>> {
    for service in services {
        service.register(&ctx);
    }
    services
        .iter()
        .map(|service| {
            let service = Arc::clone(service);
            let ctx = ctx.clone();
            tokio::spawn(async move { service.run(ctx).await })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::fs::s3::{S3Backend, S3ClientConfig};

    struct DummyService;

    #[async_trait::async_trait]
    impl ReactiveService for DummyService {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn register(&self, _ctx: &ReactiveContext) {}

        async fn run(&self, ctx: ReactiveContext) -> anyhow::Result<()> {
            ctx.cancel.cancelled().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn dummy_service_runs_until_cancelled() -> anyhow::Result<()> {
        let s3 = S3ClientConfig {
            bucket: "test-bucket".into(),
            region: "us-east-1".into(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            backend: S3Backend::Memory,
        };
        let policy_store = db::build_s3_store(&s3, "test/policy").await?;
        let policy_engine = PolicyEngine::init_s3(policy_store).await?;
        let fs_store = db::build_s3_store(&s3, "test/fs").await?;
        let fs_engine = FsEngine::init(fs_store, &s3, policy_engine.authorizer()).await?;
        let wal_store = db::build_s3_store(&s3, "test/wal").await?;
        let wal = Wal::new(wal_store);
        let cancel = CancellationToken::new();

        let ctx = ReactiveContext {
            policy: Arc::new(policy_engine),
            fs: Arc::new(fs_engine),
            wal: Arc::new(wal),
            db_prefix: "test".into(),
            s3: s3.clone(),
            cancel: cancel.clone(),
        };

        let services: Vec<Arc<dyn ReactiveService>> = vec![Arc::new(DummyService)];
        let handles = spawn_services(&services, ctx);

        cancel.cancel();
        for handle in handles {
            let result = handle.await?;
            result?;
        }
        Ok(())
    }
}
