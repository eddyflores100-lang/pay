//! Durable MPP replay store shared by every pay-api replica.
//!
//! `mpp_store_url` selects the backend: `redis://` / `rediss://` for the
//! shared Redis store, or the explicit `memory://` opt-in for a single
//! process (local development only).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use pay_api_core::Error;
use pay_kit::mpp::store::{MemoryStore, Store, StoreError};

/// Records outlive every challenge, blockhash and pending-confirmation window.
const RECORD_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Connection to the configured store backend; namespaces are cheap views.
#[derive(Clone)]
pub enum StoreBackend {
    Redis(redis::aio::ConnectionManager),
    Memory,
}

impl StoreBackend {
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let url = url.trim();
        if url == "memory://" {
            tracing::warn!("mpp_store_url is memory://: replay state is process-local");
            return Ok(Self::Memory);
        }
        if !url.starts_with("redis://") && !url.starts_with("rediss://") {
            return Err(Error::SendNotConfigured(
                "mpp_store_url must be a redis:// or rediss:// URL, or memory://".into(),
            ));
        }
        let client = redis::Client::open(url)
            .map_err(|e| Error::SendNotConfigured(format!("invalid mpp_store_url: {e}")))?;
        let connection = client
            .get_connection_manager()
            .await
            .map_err(|e| Error::SendNotConfigured(format!("mpp store unreachable: {e}")))?;
        Ok(Self::Redis(connection))
    }

    /// A store whose keys live under `namespace`.
    pub fn namespace(&self, namespace: &str) -> Arc<dyn Store> {
        match self {
            Self::Redis(connection) => Arc::new(RedisStore {
                connection: connection.clone(),
                prefix: format!("pay-api:{namespace}:"),
            }),
            Self::Memory => Arc::new(MemoryStore::new()),
        }
    }
}

struct RedisStore {
    connection: redis::aio::ConnectionManager,
    prefix: String,
}

type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

fn internal(error: redis::RedisError) -> StoreError {
    StoreError::Internal(error.to_string())
}

fn encode(value: &serde_json::Value) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|e| StoreError::Serialization(e.to_string()))
}

impl Store for RedisStore {
    fn get(&self, key: &str) -> StoreFuture<'_, Option<serde_json::Value>> {
        let mut connection = self.connection.clone();
        let key = format!("{}{key}", self.prefix);
        Box::pin(async move {
            let raw: Option<String> = redis::cmd("GET")
                .arg(key)
                .query_async(&mut connection)
                .await
                .map_err(internal)?;
            raw.map(|raw| {
                serde_json::from_str(&raw).map_err(|e| StoreError::Serialization(e.to_string()))
            })
            .transpose()
        })
    }

    fn put(&self, key: &str, value: serde_json::Value) -> StoreFuture<'_, ()> {
        let mut connection = self.connection.clone();
        let key = format!("{}{key}", self.prefix);
        Box::pin(async move {
            redis::cmd("SET")
                .arg(key)
                .arg(encode(&value)?)
                .arg("EX")
                .arg(RECORD_TTL_SECONDS)
                .query_async::<()>(&mut connection)
                .await
                .map_err(internal)
        })
    }

    fn delete(&self, key: &str) -> StoreFuture<'_, ()> {
        let mut connection = self.connection.clone();
        let key = format!("{}{key}", self.prefix);
        Box::pin(async move {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut connection)
                .await
                .map_err(internal)
        })
    }

    fn put_if_absent(&self, key: &str, value: serde_json::Value) -> StoreFuture<'_, bool> {
        let mut connection = self.connection.clone();
        let key = format!("{}{key}", self.prefix);
        Box::pin(async move {
            let set: Option<String> = redis::cmd("SET")
                .arg(key)
                .arg(encode(&value)?)
                .arg("NX")
                .arg("EX")
                .arg(RECORD_TTL_SECONDS)
                .query_async(&mut connection)
                .await
                .map_err(internal)?;
            Ok(set.is_some())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::redeem::tests::flow::spawn_redis;
    use serde_json::json;

    #[tokio::test]
    async fn rejects_unknown_store_urls() {
        for url in ["", "postgres://db", "http://redis"] {
            assert!(StoreBackend::connect(url).await.is_err(), "{url}");
        }
        assert!(matches!(
            StoreBackend::connect("memory://").await,
            Ok(StoreBackend::Memory)
        ));
    }

    #[tokio::test]
    async fn redis_namespaces_share_state_across_connections_and_stay_disjoint() {
        let Some(redis) = spawn_redis().await else {
            return;
        };
        let url = format!("redis://127.0.0.1:{}/", redis.1);
        let replica_a = StoreBackend::connect(&url).await.unwrap();
        let replica_b = StoreBackend::connect(&url).await.unwrap();

        let a = replica_a.namespace("charge");
        let b = replica_b.namespace("charge");
        assert!(a.put_if_absent("sig", json!(1)).await.unwrap());
        assert!(!b.put_if_absent("sig", json!(2)).await.unwrap());
        assert_eq!(b.get("sig").await.unwrap(), Some(json!(1)));

        let other = replica_b.namespace("confidential:mainnet");
        assert!(other.put_if_absent("sig", json!(3)).await.unwrap());

        b.delete("sig").await.unwrap();
        assert_eq!(a.get("sig").await.unwrap(), None);
        a.put("k", json!({"x": 1})).await.unwrap();
        assert_eq!(b.get("k").await.unwrap(), Some(json!({"x": 1})));
    }
}
