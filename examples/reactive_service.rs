//! Example: minimal wiring for a [`rust_api::reactive::ReactiveService`].
//!
//! The service builds a hooked store from the shared runtime and attaches an
//! `oxkv` observer. It contains no domain logic.
//!
//! Build with `cargo build --example reactive_service`.

use std::sync::Arc;

use async_trait::async_trait;
use rust_api::fs::s3::{S3Backend, S3ClientConfig};
use rust_api::reactive::{ReactiveContext, ReactiveService};
use rust_api::{db, fs, policy, sync};
use tokio_util::sync::CancellationToken;

use oxkv::{ChangeEvent, Hooks, Observer, Scope, StoreView};

struct ExampleReactiveService;

#[async_trait]
impl ReactiveService for ExampleReactiveService {
    fn name(&self) -> &'static str {
        "reactive-example"
    }

    fn register(&self, _ctx: &ReactiveContext) {
        // Keep registration cheap and synchronous. Store construction
        // happens in `run`.
    }

    async fn run(&self, ctx: ReactiveContext) -> anyhow::Result<()> {
        // Build a store from the shared runtime configuration. An
        // application would scope this prefix to its own domain.
        let store = db::build_s3_store(&ctx.s3, &format!("{}/reactive-example", ctx.db_prefix))
            .await
            .map_err(|e| anyhow::anyhow!("build reactive store: {e}"))?;

        struct ExampleObserver;

        #[async_trait]
        impl Observer for ExampleObserver {
            fn scope(&self) -> Scope {
                Scope::All
            }

            async fn on_change(&self, _ctx: &dyn StoreView, event: &ChangeEvent) {
                tracing::info!(
                    key = %event.key,
                    kind = ?event.kind,
                    "reactive example observed change"
                );
            }
        }

        store.add_observer(ExampleObserver);

        // Run until shutdown. A real service would also drain the
        // observer's work here.
        ctx.cancel.cancelled().await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // In-memory runtime, so the example runs without a server or S3.
    let s3 = S3ClientConfig {
        bucket: "example-bucket".into(),
        region: "us-east-1".into(),
        endpoint_url: None,
        force_path_style: false,
        access_key_id: None,
        secret_access_key: None,
        backend: S3Backend::Memory,
    };

    let policy_store = db::build_s3_store(&s3, "example/policy")
        .await
        .map_err(|e| anyhow::anyhow!("build policy store: {e}"))?;
    let policy_engine = policy::PolicyEngine::init_s3(policy_store)
        .await
        .map_err(|e| anyhow::anyhow!("init policy engine: {e}"))?;

    let fs_store = db::build_s3_store(&s3, "example/fs")
        .await
        .map_err(|e| anyhow::anyhow!("build fs store: {e}"))?;
    let fs_engine = fs::FsEngine::init(fs_store, &s3, policy_engine.authorizer())
        .await
        .map_err(|e| anyhow::anyhow!("init fs engine: {e}"))?;

    let wal_store = db::build_s3_store(&s3, "example/wal")
        .await
        .map_err(|e| anyhow::anyhow!("build wal store: {e}"))?;
    let wal = sync::wal::Wal::new(wal_store);

    let cancel = CancellationToken::new();
    let ctx = ReactiveContext {
        policy: Arc::new(policy_engine),
        fs: Arc::new(fs_engine),
        wal: Arc::new(wal),
        db_prefix: "example".into(),
        s3: s3.clone(),
        cancel: cancel.clone(),
    };

    let service: Arc<dyn ReactiveService> = Arc::new(ExampleReactiveService);
    service.register(&ctx);

    let services: Vec<Arc<dyn ReactiveService>> = vec![service];
    let handles = rust_api::reactive::spawn_services(&services, ctx);

    cancel.cancel();
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}
