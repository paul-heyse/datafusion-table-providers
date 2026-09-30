//! Real PostgreSQL controls for terminal bound pools. PROVIDER_TEST_URL is a disposable/local
//! operator database; each control creates and removes its own uniquely named lock table.
use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use arrow_schema::{Schema, Field, DataType};
use async_trait::async_trait;
use datafusion_table_providers_postgres::{pool::{PostgresConnectionPool, SessionBinder, BoundLimits, PoolHealth}, bounded::ChunkLimits};
use futures::TryStreamExt;
use tokio_postgres::{Client, Config, NoTls};

#[derive(Debug, Default)]
struct Binding { acquired: AtomicUsize, released: AtomicUsize }
#[async_trait]
impl SessionBinder for Binding {
    async fn bind(&self, client: &Client) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        client.batch_execute("SELECT pg_advisory_lock_shared(190930003)").await?;
        self.acquired.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn release(&self, client: &Client) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let released: bool = client.query_one("SELECT pg_advisory_unlock_shared(190930003)", &[]).await?.get(0);
        if !released { return Err("lease was not held".into()); }
        self.released.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn config() -> Config { std::env::var("PROVIDER_TEST_URL").expect("PROVIDER_TEST_URL required").parse().expect("PostgreSQL config") }
fn limits() -> BoundLimits { BoundLimits { connections: 1, acquire_timeout: Duration::from_secs(3), drain_timeout: Duration::from_secs(2) } }
fn schema() -> Arc<Schema> { Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)])) }

#[tokio::test]
async fn close_is_terminal_for_retained_pools_and_releases_each_lease_once() {
    let binding = Arc::new(Binding::default());
    let pool = Arc::new(PostgresConnectionPool::new_bound(config(), "disable", None, binding.clone(), limits()).await.unwrap());
    let retained = pool.clone();
    let rows = pool.connect_direct().await.unwrap().query_arrow_bounded("SELECT 1::bigint AS n", &[], schema(), ChunkLimits::default(), None, limits().drain_timeout).await.unwrap().try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(rows[0].num_rows(), 1);
    pool.close().await.unwrap();
    assert_eq!(retained.health(), PoolHealth::Closed);
    assert!(retained.connect_direct().await.is_err());
    retained.close().await.unwrap();
    assert_eq!(binding.acquired.load(Ordering::SeqCst), 1);
    assert_eq!(binding.released.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_before_row_stream_creation_drains_without_replacing_the_connection() {
    let (client, connection) = config().connect(NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let name = format!("provider_early_cancel_{}", client.query_one("SELECT pg_backend_pid()", &[]).await.unwrap().get::<_,i32>(0));
    client.batch_execute(&format!("CREATE TABLE {name}(n bigint NOT NULL)")).await.unwrap();
    client.batch_execute(&format!("BEGIN; LOCK TABLE {name} IN ACCESS EXCLUSIVE MODE")).await.unwrap();
    let binding = Arc::new(Binding::default());
    let pool = PostgresConnectionPool::new_bound(config(), "disable", None, binding.clone(), limits()).await.unwrap();
    let connection = pool.connect_direct().await.unwrap();
    let sql = format!("SELECT n FROM {name}");
    let future = connection.query_arrow_bounded(&sql, &[], schema(), ChunkLimits::default(), None, limits().drain_timeout);
    assert!(tokio::time::timeout(Duration::from_millis(100), future).await.is_err());
    client.batch_execute("ROLLBACK").await.unwrap();
    for _ in 0..100 {
        if matches!(pool.health(), PoolHealth::Ready { idle: 1, .. }) { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(matches!(pool.health(), PoolHealth::Ready { connections: 1, idle: 1 }));
    let rows = pool.connect_direct().await.unwrap().query_arrow_bounded("SELECT 2::bigint AS n", &[], schema(), ChunkLimits::default(), None, limits().drain_timeout).await.unwrap().try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(rows[0].num_rows(), 1);
    assert_eq!(binding.acquired.load(Ordering::SeqCst), 1);
    pool.close().await.unwrap();
    client.batch_execute(&format!("DROP TABLE IF EXISTS {name}")).await.unwrap();
    driver.abort();
}
