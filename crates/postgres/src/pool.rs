use crate::conn::PostgresConnection;
use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use async_trait::async_trait;
use bb8::ErrorSink;
use bb8_postgres::tokio_postgres::{config::Host, types::ToSql, Config};
use datafusion_table_providers_common::{
    util::{self, ns_lookup::verify_ns_lookup_and_tcp_connect},
    UnsupportedTypeAction,
};
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use snafu::{prelude::*, ResultExt};
use tokio::runtime::Handle;
use tokio_postgres;

use datafusion_table_providers_common::sql::db_connection_pool::{
    dbconnection::{AsyncDbConnection, DbConnection},
    runtime::run_async_with_tokio,
    DbConnectionPool, JoinPushDown, PasswordProvider, StaticPasswordProvider,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("PostgreSQL connection failed.\n{source}\nFor details, refer to the PostgreSQL documentation: https://www.postgresql.org/docs/17/index.html"))]
    ConnectionPoolError {
        source: bb8_postgres::tokio_postgres::Error,
    },

    #[snafu(display("PostgreSQL connection failed.\n{source}\nAdjust the connection pool parameters for sufficient capacity."))]
    ConnectionPoolRunError {
        source: bb8::RunError<bb8_postgres::tokio_postgres::Error>,
    },

    #[snafu(display(
        "Invalid parameter: {parameter_name}. Ensure the parameter name is correct."
    ))]
    InvalidParameterError { parameter_name: String },

    #[snafu(display("Could not parse {parameter_name} into a valid integer. Ensure it is configured with a valid value."))]
    InvalidIntegerParameterError {
        parameter_name: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("Cannot connect to PostgreSQL on {host}:{port}. Ensure the host and port are correct and reachable."))]
    InvalidHostOrPortError {
        source: datafusion_table_providers_common::util::ns_lookup::Error,
        host: String,
        port: u16,
    },

    #[snafu(display(
        "Invalid root certificate path: {path}. Ensure it points to a valid root certificate."
    ))]
    InvalidRootCertPathError { path: String },

    #[snafu(display(
        "Failed to read certificate.\n{source}\nEnsure the root certificate path points to a valid certificate."
    ))]
    FailedToReadCertError { source: std::io::Error },

    #[snafu(display(
        "Certificate loading failed.\n{source}\nEnsure the root certificate path points to a valid certificate."
    ))]
    FailedToLoadCertError { source: native_tls::Error },

    #[snafu(display("TLS connector initialization failed.\n{source}\nVerify SSL mode and root certificate validity"))]
    FailedToBuildTlsConnectorError { source: native_tls::Error },

    #[snafu(display("PostgreSQL connection failed.\n{source}\nFor details, refer to the PostgreSQL documentation: https://www.postgresql.org/docs/17/index.html"))]
    PostgresConnectionError { source: tokio_postgres::Error },

    #[snafu(display("Authentication failed. Verify username and password."))]
    InvalidUsernameOrPassword { source: tokio_postgres::Error },

    #[snafu(display("Password provider error.\n{source}"))]
    PasswordProviderError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("Task failed to execute on IO runtime.\n{source}"))]
    IoRuntimeError { source: tokio::task::JoinError },

    #[snafu(display("The bound PostgreSQL pool is lost: a connection closed or a cancelled read could not be drained. It never reconnects."))]
    BoundPoolLost,

    #[snafu(display("Binding a PostgreSQL session failed.\n{source}"))]
    SessionBindError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error type for the connection manager, covering both Postgres and password provider errors.
#[derive(Debug)]
pub enum ConnectionManagerError {
    /// An error from the underlying Postgres connection.
    Postgres(tokio_postgres::Error),
    /// An error from the password provider.
    PasswordProvider(Box<dyn std::error::Error + Send + Sync>),
    /// A bound pool may not open a connection beyond its prefilled set.
    Lost,
    /// The session binder refused a new connection.
    Bind(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for ConnectionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres(e) => write!(f, "{e}"),
            Self::PasswordProvider(e) => write!(f, "password provider error: {e}"),
            Self::Lost => write!(f, "bound pool lost; it never reconnects"),
            Self::Bind(e) => write!(f, "session binding failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectionManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Postgres(e) => Some(e),
            Self::PasswordProvider(e) | Self::Bind(e) => Some(e.as_ref()),
            Self::Lost => None,
        }
    }
}

impl From<tokio_postgres::Error> for ConnectionManagerError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Postgres(e)
    }
}

/// A bb8 connection manager that supports dynamic password providers.
///
/// When a [`PasswordProvider`] is set, the manager calls it to get a fresh password
/// each time a new connection is created. This enables rotating credentials,
/// JWT-based auth, and cloud IAM authentication.
///
/// When no provider is set (passwordless auth), the manager connects using the
/// stored [`Config`] as-is.
#[derive(Debug, Default)]
pub struct ReadMetrics {
    pub query_wait_ns: std::sync::atomic::AtomicU64,
    pub conversion_ns: std::sync::atomic::AtomicU64,
    pub rows: std::sync::atomic::AtomicU64,
}
impl ReadMetrics {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.query_wait_ns.load(Relaxed),
            self.conversion_ns.load(Relaxed),
            self.rows.load(Relaxed),
        )
    }
}
pub struct ConnectionManager {
    metrics: Arc<ReadMetrics>,
    permits: Arc<tokio::sync::Semaphore>,
    config: Config,
    tls: MakeTlsConnector,
    password_provider: Option<Arc<dyn PasswordProvider>>,
    bound: Option<Bound>,
}

/// Binds each physical connection to its caller's session once, before first use: for example,
/// by holding a lease on the data it reads and checking that data's identity. A bound pool opens
/// exactly its prefilled connections and never reconnects, so a binding is never silently
/// replaced by another.
#[async_trait]
pub trait SessionBinder: Send + Sync + std::fmt::Debug {
    async fn bind(
        &self,
        client: &tokio_postgres::Client,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Release caller-owned session state before physical close. Called once during terminal close.
    async fn release(&self, _client: &tokio_postgres::Client) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
}

/// Limits of a bound pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundLimits {
    pub connections: u32,
    pub acquire_timeout: std::time::Duration,
    /// How long a cancelled read may take to drain before the pool is lost.
    pub drain_timeout: std::time::Duration,
}

/// A bound pool is ready until it is lost; loss is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolHealth {
    Ready { connections: u32, idle: u32 },
    Closing,
    Closed,
    Lost,
}

// 0 ready, 1 closing, 2 closed, 3 lost. All connections and retained tables share one state.
struct BoundState {
    health: std::sync::atomic::AtomicU8,
    connections: std::sync::Mutex<Vec<ConnectionEnd>>,
    close: tokio::sync::Mutex<()>,
    binder: Arc<dyn SessionBinder>,
}
impl std::fmt::Debug for BoundState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundState").field("health", &self.health.load(std::sync::atomic::Ordering::Acquire)).finish()
    }
}
#[derive(Clone)]
struct ConnectionEnd {
    cancel: tokio_postgres::CancelToken,
    task: tokio::task::AbortHandle,
    tls: MakeTlsConnector,
    streaming: Arc<std::sync::atomic::AtomicBool>,
}
impl BoundState {
    fn ready(&self) -> bool { self.health.load(std::sync::atomic::Ordering::Acquire) == 0 }
    fn lose(&self) { let _ = self.health.compare_exchange(0, 3, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire); }
}

#[derive(Debug)]
struct Bound {
    binder: Arc<dyn SessionBinder>,
    remaining: std::sync::atomic::AtomicU32,
    state: Arc<BoundState>,
}

impl ConnectionManager {
    fn new(config: Config, tls: MakeTlsConnector, capacity: u32) -> Self {
        Self {
            config,
            tls,
            password_provider: None,
            metrics: Arc::default(),
            permits: Arc::new(tokio::sync::Semaphore::new(capacity as usize)),
            bound: None,
        }
    }

    fn with_password_provider(mut self, provider: Arc<dyn PasswordProvider>) -> Self {
        self.password_provider = Some(provider);
        self
    }
}

/// Applies per-connection session configuration after a connection is established.
///
/// Redshift surfaces Spectrum complex external columns (`ARRAY`/`STRUCT`/`MAP`) and
/// `SUPER` values as JSON text only when `json_serialization_enable` is on; otherwise
/// selecting such a column errors server-side. `json_serialization_parse_nested_strings`
/// additionally renders nested string fields that hold valid JSON inline (unescaped)
/// rather than as escaped string literals, so the decoded values match their schema.
///
/// These parameters only exist on Redshift, so rather than spend a `SELECT version()`
/// round-trip detecting the variant we apply them optimistically and treat vanilla
/// PostgreSQL's "unrecognized configuration parameter" error (`SQLSTATE 42704`) as a
/// no-op. The `SET`s run outside a transaction, so a failure leaves the connection
/// usable.
///
/// See <https://docs.aws.amazon.com/redshift/latest/dg/r_json_serialization_enable.html>
/// and <https://docs.aws.amazon.com/redshift/latest/dg/r_json_serialization_parse_nested_strings.html>.
async fn configure_session(
    client: &tokio_postgres::Client,
) -> std::result::Result<(), ConnectionManagerError> {
    if let Err(e) = client
        .batch_execute(
            "SET json_serialization_enable TO true; \
             SET json_serialization_parse_nested_strings TO true;",
        )
        .await
    {
        // Vanilla PostgreSQL rejects these unknown parameters with `undefined_object`
        // (42704); that just means "not Redshift", so ignore it. Anything else is real.
        if e.code() == Some(&tokio_postgres::error::SqlState::UNDEFINED_OBJECT) {
            return Ok(());
        }
        return Err(e.into());
    }

    Ok(())
}

/// A lease retains physical capacity until cancelled server work has drained.
pub struct ManagedClient {
    connection_task: tokio::task::AbortHandle,
    pub(crate) metrics: Arc<ReadMetrics>,
    client: Option<tokio_postgres::Client>,
    tls: MakeTlsConnector,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(crate) streaming: Arc<std::sync::atomic::AtomicBool>,
    /// A bound pool's terminal loss flag, shared by all of its connections.
    state: Option<Arc<BoundState>>,
}
impl std::fmt::Debug for ManagedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedClient")
            .field("streaming", &self.streaming)
            .finish_non_exhaustive()
    }
}
impl Drop for ManagedClient {
    fn drop(&mut self) {
        if self.streaming.load(std::sync::atomic::Ordering::Acquire) {
            if let Ok(runtime) = Handle::try_current() {
                let client = self.client.take().expect("owned client");
                let tls = self.tls.clone();
                let task = self.connection_task.clone();
                let permit = self.permit.take().expect("owned capacity");
                runtime.spawn(async move {
                    // Sending CancelRequest alone has no acknowledgement. A subsequent
                    // round trip proves the original request has left the server.
                    let drained = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        client.cancel_token().cancel_query(tls).await?;
                        client.simple_query("").await?;
                        Ok::<_, tokio_postgres::Error>(())
                    })
                    .await;
                    if !matches!(drained, Ok(Ok(()))) {
                        // Uncertain server work must not create extra pool capacity.
                        // This slot stays quarantined until the pool is recreated.
                        permit.forget();
                        tracing::warn!("postgres cancellation unconfirmed; pool slot quarantined");
                    }
                    task.abort();
                });
                return;
            }
        }
        self.connection_task.abort();
    }
}
impl ManagedClient {
    /// Cancel the in-flight request and prove it left the server: CancelRequest has no
    /// acknowledgement, so a following round trip confirms the drain.
    pub async fn drain(&self) -> std::result::Result<(), tokio_postgres::Error> {
        self.cancel_token().cancel_query(self.tls.clone()).await?;
        self.simple_query("").await?;
        Ok(())
    }
    /// Mark the bound pool this connection belongs to as lost.
    pub fn mark_lost(&self) {
        if let Some(state) = &self.state { state.lose(); }
    }
    pub fn start_request(&self) -> Result<()> {
        if self.state.as_ref().is_some_and(|s| !s.ready()) { return BoundPoolLostSnafu.fail(); }
        self.streaming.store(true, std::sync::atomic::Ordering::Release);
        if self.state.as_ref().is_some_and(|s| !s.ready()) {
            self.streaming.store(false, std::sync::atomic::Ordering::Release);
            return BoundPoolLostSnafu.fail();
        }
        Ok(())
    }
    pub fn finish_request(&self) {
        self.streaming
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
impl std::ops::Deref for ManagedClient {
    type Target = tokio_postgres::Client;
    fn deref(&self) -> &Self::Target {
        self.client.as_ref().expect("owned client")
    }
}
impl std::ops::DerefMut for ManagedClient {
    fn deref_mut(&mut self) -> &mut Self::Target { self.client.as_mut().expect("owned client") }
}
impl bb8::ManageConnection for ConnectionManager {
    type Connection = ManagedClient;
    type Error = ConnectionManagerError;

    async fn connect(&self) -> std::result::Result<ManagedClient, ConnectionManagerError> {
        if let Some(bound) = &self.bound {
            use std::sync::atomic::Ordering;
            if !bound.state.ready() { return Err(ConnectionManagerError::Lost); }
            if bound.remaining.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1)).is_err() {
                bound.state.lose();
                return Err(ConnectionManagerError::Lost);
            }
        }
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("capacity semaphore never closed");
        let (client, connection) = if let Some(provider) = &self.password_provider {
            let password = provider
                .get_password()
                .await
                .map_err(ConnectionManagerError::PasswordProvider)?;
            let mut config = self.config.clone();
            config.password(password.expose_secret());
            config.connect(self.tls.clone()).await?
        } else {
            self.config.connect(self.tls.clone()).await?
        };
        let task = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("postgres connection error: {e}");
            }
        });

        let managed = ManagedClient {
            client: Some(client),
            tls: self.tls.clone(),
            permit: Some(permit),
            connection_task: task.abort_handle(),
            metrics: self.metrics.clone(),
            streaming: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            state: self.bound.as_ref().map(|bound| bound.state.clone()),
        };
        configure_session(&managed).await?;
        if let Some(bound) = &self.bound {
            bound.binder.bind(&managed).await.map_err(ConnectionManagerError::Bind)?;
            bound.state.connections.lock().expect("connection registry").push(ConnectionEnd {
                cancel: managed.cancel_token(),
                task: managed.connection_task.clone(), tls: managed.tls.clone(), streaming: managed.streaming.clone(),
            });
        }
        Ok(managed)
    }

    async fn is_valid(
        &self,
        conn: &mut ManagedClient,
    ) -> std::result::Result<(), ConnectionManagerError> {
        conn.simple_query("").await.map(|_| ())?;
        Ok(())
    }

    fn has_broken(&self, conn: &mut ManagedClient) -> bool {
        let broken = conn.is_closed() || conn.streaming.load(std::sync::atomic::Ordering::Acquire);
        if broken {
            // A bound connection is never replaced; losing one loses the pool.
            conn.mark_lost();
        }
        broken
    }
}

#[derive(Debug)]
pub struct PostgresConnectionPool {
    metrics: Arc<ReadMetrics>,
    pool: Arc<bb8::Pool<ConnectionManager>>,
    join_push_down: JoinPushDown,
    unsupported_type_action: UnsupportedTypeAction,
    io_handle: Option<Handle>,
    state: Option<Arc<BoundState>>,
    drain_timeout: std::time::Duration,
}

impl PostgresConnectionPool {
    pub fn read_metrics(&self) -> (u64, u64, u64) {
        self.metrics.snapshot()
    }

    /// Create a bounded pool from a typed connection configuration. No connection-string
    /// interpolation is needed, and the caller controls session options before connecting.
    pub async fn new_with_config(
        config: Config,
        ssl_mode: &str,
        rootcert: Option<PathBuf>,
        max_connections: u32,
        acquire_timeout: std::time::Duration,
    ) -> Result<Self> {
        if !(1..=32).contains(&max_connections)
            || acquire_timeout.is_zero()
            || acquire_timeout.as_secs() > 60
        {
            return InvalidParameterSnafu {
                parameter_name: "pool limits".to_string(),
            }
            .fail();
        }
        let certs = match rootcert {
            Some(path) => {
                let bytes = tokio::fs::read(path).await.context(FailedToReadCertSnafu)?;
                Some(parse_certs(&bytes)?)
            }
            None => None,
        };
        let tls = get_tls_connector(ssl_mode, certs)?;
        let join_push_down = get_join_context(&config);
        let manager = ConnectionManager::new(config, MakeTlsConnector::new(tls), max_connections);
        let metrics = manager.metrics.clone();
        let pool = bb8::Pool::builder()
            .max_size(max_connections)
            .connection_timeout(acquire_timeout)
            .idle_timeout(Some(std::time::Duration::from_secs(60)))
            .max_lifetime(Some(std::time::Duration::from_secs(1800)))
            .error_sink(Box::new(PostgresErrorSink::new()))
            .build(manager)
            .await
            .map_err(map_pool_build_error)?;
        {
            let conn = pool.get().await.map_err(map_pool_run_error)?;
            conn.execute("SELECT 1", &[])
                .await
                .context(ConnectionPoolSnafu)?;
        }
        Ok(Self {
            metrics,
            pool: Arc::new(pool),
            join_push_down,
            unsupported_type_action: UnsupportedTypeAction::Error,
            io_handle: None,
            state: None,
            drain_timeout: std::time::Duration::from_secs(2),
        })
    }

    /// Create a bound pool: exactly `limits.connections` connections, opened and bound by
    /// `binder` before this returns, never reaped and never replaced. A closed connection or a
    /// cancelled read that cannot be drained within `limits.drain_timeout` loses the pool, and
    /// every later acquisition is refused.
    pub async fn new_bound(
        config: Config,
        ssl_mode: &str,
        rootcert: Option<PathBuf>,
        binder: Arc<dyn SessionBinder>,
        limits: BoundLimits,
    ) -> Result<Self> {
        if !(1..=32).contains(&limits.connections)
            || limits.acquire_timeout.is_zero()
            || limits.acquire_timeout.as_secs() > 60
            || limits.drain_timeout.is_zero()
            || limits.drain_timeout.as_secs() > 60
        {
            return InvalidParameterSnafu {
                parameter_name: "bound pool limits".to_string(),
            }
            .fail();
        }
        let certs = match rootcert {
            Some(path) => {
                let bytes = tokio::fs::read(path).await.context(FailedToReadCertSnafu)?;
                Some(parse_certs(&bytes)?)
            }
            None => None,
        };
        let tls = get_tls_connector(ssl_mode, certs)?;
        let join_push_down = get_join_context(&config);
        let state = Arc::new(BoundState { health: std::sync::atomic::AtomicU8::new(0),
            connections: Default::default(), close: Default::default(), binder: binder.clone() });
        let mut manager = ConnectionManager::new(config, MakeTlsConnector::new(tls), limits.connections);
        manager.bound = Some(Bound {
            binder,
            remaining: std::sync::atomic::AtomicU32::new(limits.connections),
            state: state.clone(),
        });
        let metrics = manager.metrics.clone();
        let pool = bb8::Pool::builder()
            .max_size(limits.connections)
            .min_idle(Some(limits.connections))
            .connection_timeout(limits.acquire_timeout)
            .idle_timeout(None)
            .max_lifetime(None)
            .error_sink(Box::new(PostgresErrorSink::new()))
            .build(manager)
            .await
            .map_err(map_pool_build_error)?;
        let counts = pool.state();
        if counts.connections != limits.connections || !state.ready() {
            return BoundPoolLostSnafu.fail();
        }
        Ok(Self {
            metrics,
            pool: Arc::new(pool),
            join_push_down,
            unsupported_type_action: UnsupportedTypeAction::Error,
            io_handle: None,
            state: Some(state),
            drain_timeout: limits.drain_timeout,
        })
    }

    /// Whether a bound pool can still serve reads, and its connection counts. An unbound pool
    /// is never lost.
    pub fn health(&self) -> PoolHealth {
        if let Some(state) = &self.state {
            match state.health.load(std::sync::atomic::Ordering::Acquire) {
                1 => return PoolHealth::Closing,
                2 => return PoolHealth::Closed,
                3 => return PoolHealth::Lost,
                _ => {}
            }
        }
        let state = self.pool.state();
        PoolHealth::Ready {
            connections: state.connections,
            idle: state.idle_connections,
        }
    }

    fn is_lost(&self) -> bool {
        self.state.as_ref().is_some_and(|state| !state.ready())
    }

    /// Terminal close shared by every retained table and connection. Stop new requests first,
    /// drain within one deadline, release caller state, and physically close every transport.
    /// A failed close is terminal loss and still aborts all transports; it never reconnects.
    pub async fn close(&self) -> Result<()> {
        use std::sync::atomic::Ordering::{Acquire, Release};
        let state = self.state.as_ref().ok_or(Error::InvalidParameterError { parameter_name: "close requires a bound pool".into() })?;
        let _closing = state.close.lock().await;
        if state.health.load(Acquire) == 2 { return Ok(()); }
        let mut healthy = state.health.load(Acquire) == 0;
        state.health.store(1, Release);
        let connections = state.connections.lock().expect("connection registry").clone();
        // This guard also makes cancellation of close terminal and closes every transport.
        struct Closing<'a> { state: &'a BoundState, connections: Vec<ConnectionEnd>, finished: bool }
        impl Drop for Closing<'_> {
            fn drop(&mut self) {
                for connection in &self.connections { connection.task.abort(); }
                if !self.finished { self.state.health.store(3, std::sync::atomic::Ordering::Release); }
            }
        }
        let mut closing = Closing { state, connections, finished: false };
        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        // Ask every active backend to cancel before waiting for checked-out leases. Their
        // request guards own the acknowledgement and keep their pool slots until it arrives.
        for connection in &closing.connections {
            if connection.streaming.load(Acquire) {
                let cancelled = tokio::time::timeout_at(deadline, connection.cancel.cancel_query(connection.tls.clone())).await;
                healthy &= matches!(cancelled, Ok(Ok(())));
            }
        }
        let mut held = Vec::new();
        for _ in &closing.connections {
            match tokio::time::timeout_at(deadline, self.pool.get_owned()).await {
                Ok(Ok(connection)) => {
                    healthy &= matches!(tokio::time::timeout_at(deadline, state.binder.release(&connection)).await, Ok(Ok(())));
                    held.push(connection);
                }
                _ => { healthy = false; break; }
            }
        }
        for connection in &closing.connections { connection.task.abort(); }
        state.health.store(if healthy { 2 } else { 3 }, Release);
        closing.finished = true;
        if healthy { Ok(()) } else { BoundPoolLostSnafu.fail() }
    }

    /// How long a cancelled read on this pool may take to drain.
    pub fn drain_timeout(&self) -> std::time::Duration {
        self.drain_timeout
    }

    /// Creates a new instance of `PostgresConnectionPool`.
    ///
    /// If a `pass` parameter is present, it is wrapped in a [`StaticPasswordProvider`]
    /// internally. For dynamic credentials, use [`new_with_password_provider`](Self::new_with_password_provider).
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem creating the connection pool.
    pub async fn new(params: HashMap<String, SecretString>) -> Result<Self> {
        Self::new_inner(params, None).await
    }

    /// Creates a new instance of `PostgresConnectionPool` with a dynamic password provider.
    ///
    /// The password provider is called each time a new connection is created in the pool,
    /// enabling support for rotating credentials, JWT tokens, and cloud IAM authentication.
    ///
    /// Any `pass` parameter in `params` is ignored; the provider is used instead.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem creating the connection pool.
    pub async fn new_with_password_provider(
        params: HashMap<String, SecretString>,
        password_provider: Arc<dyn PasswordProvider>,
    ) -> Result<Self> {
        Self::new_inner(params, Some(password_provider)).await
    }

    async fn new_inner(
        params: HashMap<String, SecretString>,
        password_provider: Option<Arc<dyn PasswordProvider>>,
    ) -> Result<Self> {
        // Remove the "pg_" prefix from the keys to keep backward compatibility
        let params = util::remove_prefix_from_hashmap_keys(params, "pg_");

        let mut connection_string = String::new();
        let mut ssl_mode = "verify-full".to_string();
        let mut ssl_rootcert_path: Option<PathBuf> = None;
        let mut static_password: Option<SecretString> = None;

        if let Some(pg_connection_string) = params
            .get("connection_string")
            .map(SecretBox::expose_secret)
        {
            let (str, mode, cert_path, password) = parse_connection_string(pg_connection_string);
            connection_string = str;
            ssl_mode = mode;
            if password_provider.is_none() {
                static_password = password.map(SecretString::from);
            }
            if let Some(cert_path) = cert_path {
                let sslrootcert = cert_path.as_str();
                ensure!(
                    std::path::Path::new(sslrootcert).exists(),
                    InvalidRootCertPathSnafu { path: cert_path }
                );
                ssl_rootcert_path = Some(PathBuf::from(sslrootcert));
            }
        } else {
            if let Some(pg_host) = params.get("host").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("host={pg_host} ").as_str());
            }
            if let Some(pg_user) = params.get("user").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("user={pg_user} ").as_str());
            }
            if let Some(pg_db) = params.get("db").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("dbname={pg_db} ").as_str());
            }
            if password_provider.is_none() {
                if let Some(pg_pass) = params.get("pass") {
                    static_password = Some(pg_pass.clone());
                }
            }
            if let Some(pg_port) = params.get("port").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("port={pg_port} ").as_str());
            }
        }

        if let Some(pg_sslmode) = params.get("sslmode").map(SecretBox::expose_secret) {
            match pg_sslmode.to_lowercase().as_str() {
                "disable" | "require" | "prefer" | "verify-ca" | "verify-full" => {
                    ssl_mode = pg_sslmode.to_string();
                }
                _ => {
                    InvalidParameterSnafu {
                        parameter_name: "sslmode".to_string(),
                    }
                    .fail()?;
                }
            }
        }
        if let Some(pg_sslrootcert) = params.get("sslrootcert").map(SecretBox::expose_secret) {
            ensure!(
                std::path::Path::new(pg_sslrootcert).exists(),
                InvalidRootCertPathSnafu {
                    path: pg_sslrootcert,
                }
            );

            ssl_rootcert_path = Some(PathBuf::from(pg_sslrootcert));
        }

        let mode = match ssl_mode.as_str() {
            "disable" => "disable",
            "prefer" => "prefer",
            // tokio_postgres supports only disable, require and prefer
            _ => "require",
        };

        // Password is never included in the connection string — it flows
        // through the PasswordProvider on each connection instead.
        connection_string.push_str(format!("sslmode={mode} ").as_str());
        let mut config =
            Config::from_str(connection_string.as_str()).context(ConnectionPoolSnafu)?;

        apply_optional_session_params(&mut config, &params);

        verify_postgres_config(&config).await?;

        let mut certs: Option<Vec<Certificate>> = None;

        if let Some(path) = ssl_rootcert_path {
            let buf = tokio::fs::read(path).await.context(FailedToReadCertSnafu)?;
            certs = Some(parse_certs(&buf)?);
        }

        let tls_connector = get_tls_connector(ssl_mode.as_str(), certs)?;
        let connector = MakeTlsConnector::new(tls_connector);

        // Resolve the password provider: use the caller's, wrap the static password,
        // or leave as None for passwordless auth (trust, cert, etc.).
        let password_provider = password_provider.or_else(|| {
            static_password
                .map(|pw| Arc::new(StaticPasswordProvider::new(pw)) as Arc<dyn PasswordProvider>)
        });

        // Test the connection
        if let Some(ref provider) = password_provider {
            let password = provider
                .get_password()
                .await
                .map_err(|source| Error::PasswordProviderError { source })?;
            let mut test_config = config.clone();
            test_config.password(password.expose_secret());
            test_connection(&test_config, connector.clone()).await?;
        } else {
            test_connection(&config, connector.clone()).await?;
        }

        let join_push_down = get_join_context(&config);

        let mut connection_pool_size = 10; // The BB8 default is 10
        if let Some(pg_pool_size) = params
            .get("connection_pool_size")
            .map(SecretBox::expose_secret)
        {
            connection_pool_size = pg_pool_size.parse().context(InvalidIntegerParameterSnafu {
                parameter_name: "pool_size".to_string(),
            })?;
        }

        let mut manager = ConnectionManager::new(config, connector, connection_pool_size);
        if let Some(provider) = password_provider {
            manager = manager.with_password_provider(provider);
        }
        let error_sink = PostgresErrorSink::new();

        let metrics = manager.metrics.clone();
        let pool = bb8::Pool::builder()
            .max_size(connection_pool_size)
            .error_sink(Box::new(error_sink))
            .build(manager)
            .await
            .map_err(map_pool_build_error)?;

        // Verify the pool by executing a simple query
        {
            let conn = pool.get().await.map_err(map_pool_run_error)?;
            conn.execute("SELECT 1", &[])
                .await
                .context(ConnectionPoolSnafu)?;
        }

        Ok(PostgresConnectionPool {
            metrics,
            pool: Arc::new(pool),
            join_push_down,
            unsupported_type_action: UnsupportedTypeAction::default(),
            io_handle: None,
            state: None,
            drain_timeout: std::time::Duration::from_secs(2),
        })
    }

    /// Specify the action to take when an invalid type is encountered.
    #[must_use]
    pub fn with_unsupported_type_action(mut self, action: UnsupportedTypeAction) -> Self {
        self.unsupported_type_action = action;
        self
    }

    /// Route all Postgres connection background tasks to a dedicated IO runtime.
    #[must_use]
    pub fn with_io_runtime(mut self, handle: Handle) -> Self {
        self.io_handle = Some(handle);
        self
    }

    /// Returns a direct connection to the underlying database.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem creating the connection pool.
    pub async fn connect_direct(&self) -> Result<PostgresConnection> {
        if self.is_lost() {
            return BoundPoolLostSnafu.fail();
        }
        let pool = Arc::clone(&self.pool);
        let conn = if let Some(handle) = &self.io_handle {
            handle
                .spawn(async move { pool.get_owned().await.map_err(map_pool_run_error) })
                .await
                .context(IoRuntimeSnafu)??
        } else {
            pool.get_owned().await.map_err(map_pool_run_error)?
        };
        if self.is_lost() { return BoundPoolLostSnafu.fail(); }
        Ok(PostgresConnection::new(conn))
    }
}

/// Parses a connection string into components, extracting `sslmode`, `sslrootcert`,
/// and `password` separately so they can be handled by the caller.
fn parse_connection_string(
    pg_connection_string: &str,
) -> (String, String, Option<String>, Option<String>) {
    let mut connection_string = String::new();
    let mut ssl_mode = "verify-full".to_string();
    let mut ssl_rootcert_path: Option<String> = None;
    let mut password: Option<String> = None;

    let str_params: Vec<&str> = pg_connection_string.split_whitespace().collect();
    for param in str_params {
        let param = param.split('=').collect::<Vec<&str>>();
        if let (Some(&name), Some(&value)) = (param.first(), param.get(1)) {
            match name {
                "sslmode" => {
                    ssl_mode = value.to_string();
                }
                "sslrootcert" => {
                    ssl_rootcert_path = Some(value.to_string());
                }
                "password" => {
                    password = Some(value.to_string());
                }
                _ => {
                    connection_string.push_str(format!("{name}={value} ").as_str());
                }
            }
        }
    }

    (connection_string, ssl_mode, ssl_rootcert_path, password)
}

/// Apply the optional string session params libpq forwards verbatim to the
/// backend — `application_name` and `options` — onto a parsed [`Config`]. Split
/// out of `new_inner` so it is unit-testable without a live server.
///
/// `options` is the libpq `options` connection parameter: arbitrary command-line
/// switches sent at connection time (e.g. `-c statement_timeout=5000`), applied via
/// [`Config::options`]. It lets a caller pin session-level GUCs
/// (`statement_timeout`, `default_transaction_read_only`, …) that `Config` has no
/// dedicated setter for.
fn apply_optional_session_params(config: &mut Config, params: &HashMap<String, SecretString>) {
    if let Some(application_name) = params.get("application_name").map(SecretBox::expose_secret) {
        config.application_name(application_name);
    }
    if let Some(options) = params.get("options").map(SecretBox::expose_secret) {
        config.options(options);
    }
}

fn get_join_context(config: &Config) -> JoinPushDown {
    let mut join_push_context_str = String::new();
    for host in config.get_hosts() {
        join_push_context_str.push_str(&format!("host={host:?},"));
    }
    if !config.get_ports().is_empty() {
        join_push_context_str.push_str(&format!("port={port},", port = config.get_ports()[0]));
    }
    if let Some(dbname) = config.get_dbname() {
        join_push_context_str.push_str(&format!("db={dbname},"));
    }
    if let Some(user) = config.get_user() {
        join_push_context_str.push_str(&format!("user={user},"));
    }

    JoinPushDown::AllowedFor(join_push_context_str)
}

/// Classifies a connection error, returning a more specific error variant for
/// authentication failures.
fn classify_connection_error(err: tokio_postgres::Error) -> Error {
    if let Some(code) = err.code() {
        if *code == tokio_postgres::error::SqlState::INVALID_PASSWORD {
            return Error::InvalidUsernameOrPassword { source: err };
        }
    }
    Error::PostgresConnectionError { source: err }
}

async fn test_connection(config: &Config, connector: MakeTlsConnector) -> Result<()> {
    config
        .connect(connector)
        .await
        .map(|_| ())
        .map_err(classify_connection_error)
}

fn map_pool_build_error(e: ConnectionManagerError) -> Error {
    match e {
        ConnectionManagerError::Postgres(e) => Error::ConnectionPoolError { source: e },
        ConnectionManagerError::PasswordProvider(e) => Error::PasswordProviderError { source: e },
        ConnectionManagerError::Lost => Error::BoundPoolLost,
        ConnectionManagerError::Bind(e) => Error::SessionBindError { source: e },
    }
}

fn map_pool_run_error(e: bb8::RunError<ConnectionManagerError>) -> Error {
    match e {
        bb8::RunError::User(ConnectionManagerError::Postgres(e)) => Error::ConnectionPoolRunError {
            source: bb8::RunError::User(e),
        },
        bb8::RunError::User(ConnectionManagerError::PasswordProvider(e)) => {
            Error::PasswordProviderError { source: e }
        }
        bb8::RunError::User(ConnectionManagerError::Lost) => Error::BoundPoolLost,
        bb8::RunError::User(ConnectionManagerError::Bind(e)) => Error::SessionBindError { source: e },
        bb8::RunError::TimedOut => Error::ConnectionPoolRunError {
            source: bb8::RunError::TimedOut,
        },
    }
}

async fn verify_postgres_config(config: &Config) -> Result<()> {
    for host in config.get_hosts() {
        for port in config.get_ports() {
            if let Host::Tcp(host) = host {
                verify_ns_lookup_and_tcp_connect(host, *port)
                    .await
                    .context(InvalidHostOrPortSnafu { host, port: *port })?;
            }
        }
    }

    Ok(())
}

fn get_tls_connector(ssl_mode: &str, rootcerts: Option<Vec<Certificate>>) -> Result<TlsConnector> {
    let mut builder = TlsConnector::builder();

    if ssl_mode == "disable" {
        return builder.build().context(FailedToBuildTlsConnectorSnafu);
    }

    if let Some(certs) = rootcerts {
        for cert in certs {
            builder.add_root_certificate(cert);
        }
    }

    builder
        .danger_accept_invalid_hostnames(ssl_mode != "verify-full")
        .danger_accept_invalid_certs(ssl_mode != "verify-full" && ssl_mode != "verify-ca")
        .build()
        .context(FailedToBuildTlsConnectorSnafu)
}

fn parse_certs(buf: &[u8]) -> Result<Vec<Certificate>> {
    Certificate::from_der(buf)
        .map(|x| vec![x])
        .or_else(|_| {
            pem::parse_many(buf)
                .unwrap_or_default()
                .iter()
                .map(pem::encode)
                .map(|s| Certificate::from_pem(s.as_bytes()))
                .collect()
        })
        .context(FailedToLoadCertSnafu)
}

#[derive(Debug, Clone, Copy)]
struct PostgresErrorSink {}

impl PostgresErrorSink {
    pub fn new() -> Self {
        PostgresErrorSink {}
    }
}

impl<E> ErrorSink<E> for PostgresErrorSink
where
    E: std::fmt::Debug,
    E: std::fmt::Display,
{
    fn sink(&self, error: E) {
        tracing::debug!("Postgres Pool Error: {}", error);
    }

    fn boxed_clone(&self) -> Box<dyn ErrorSink<E>> {
        Box::new(*self)
    }
}

#[async_trait]
impl
    DbConnectionPool<bb8::PooledConnection<'static, ConnectionManager>, &'static (dyn ToSql + Sync)>
    for PostgresConnectionPool
{
    async fn connect(
        &self,
    ) -> std::result::Result<
        Box<
            dyn DbConnection<
                bb8::PooledConnection<'static, ConnectionManager>,
                &'static (dyn ToSql + Sync),
            >,
        >,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let pool = Arc::clone(&self.pool);
        let conn = if let Some(handle) = &self.io_handle {
            handle
                .spawn(async move { pool.get_owned().await.map_err(map_pool_run_error) })
                .await
                .context(IoRuntimeSnafu)??
        } else {
            let get_conn = async || pool.get_owned().await.map_err(map_pool_run_error);
            run_async_with_tokio(get_conn).await?
        };
        Ok(Box::new(
            PostgresConnection::new(conn)
                .with_unsupported_type_action(self.unsupported_type_action),
        ))
    }

    fn join_push_down(&self) -> JoinPushDown {
        self.join_push_down.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn static_password_provider_returns_password() {
        let provider = StaticPasswordProvider::new(SecretString::from("hunter2".to_string()));
        let password = provider.get_password().await.unwrap();
        assert_eq!(password.expose_secret(), "hunter2");
    }

    #[test]
    fn connection_manager_error_display() {
        let err = ConnectionManagerError::PasswordProvider("token expired".into());
        assert_eq!(err.to_string(), "password provider error: token expired");
    }

    #[test]
    fn connection_manager_error_implements_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(ConnectionManagerError::PasswordProvider("fail".into()));
        assert!(err.source().is_some());
    }

    #[test]
    fn parse_connection_string_extracts_password() {
        let (conn_str, ssl_mode, cert_path, password) = parse_connection_string(
            "host=localhost user=postgres password=secret dbname=mydb sslmode=disable",
        );
        assert_eq!(conn_str.trim(), "host=localhost user=postgres dbname=mydb");
        assert_eq!(ssl_mode, "disable");
        assert!(cert_path.is_none());
        assert_eq!(password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_connection_string_without_password() {
        let (conn_str, _ssl_mode, _cert_path, password) =
            parse_connection_string("host=localhost user=postgres dbname=mydb");
        assert_eq!(conn_str.trim(), "host=localhost user=postgres dbname=mydb");
        assert!(password.is_none());
    }

    #[test]
    fn options_param_reaches_the_config() {
        let mut params: HashMap<String, SecretString> = HashMap::new();
        params.insert(
            "options".to_string(),
            SecretString::from("-c statement_timeout=5000".to_string()),
        );
        params.insert(
            "application_name".to_string(),
            SecretString::from("semvia".to_string()),
        );

        let mut config = Config::new();
        apply_optional_session_params(&mut config, &params);

        assert_eq!(config.get_options(), Some("-c statement_timeout=5000"));
        assert_eq!(config.get_application_name(), Some("semvia"));
    }

    #[test]
    fn absent_options_param_leaves_the_config_untouched() {
        let params: HashMap<String, SecretString> = HashMap::new();

        let mut config = Config::new();
        apply_optional_session_params(&mut config, &params);

        assert_eq!(config.get_options(), None);
        assert_eq!(config.get_application_name(), None);
    }
}

#[cfg(test)]
mod bounded_pool_tests {
    use super::*;
    #[derive(Debug)]
    struct Unused;
    #[async_trait]
    impl SessionBinder for Unused {
        async fn bind(&self, _: &tokio_postgres::Client) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
            unreachable!("limits are refused before any connection")
        }
    }
    #[tokio::test]
    async fn bound_limits_are_rejected_before_network_access() {
        let second = std::time::Duration::from_secs(1);
        for (connections, acquire, drain) in [(0, second, second), (33, second, second), (2, std::time::Duration::ZERO, second), (2, second, std::time::Duration::ZERO)] {
            let limits = BoundLimits { connections, acquire_timeout: acquire, drain_timeout: drain };
            assert!(matches!(PostgresConnectionPool::new_bound(Config::new(), "disable", None, Arc::new(Unused), limits).await,
                Err(Error::InvalidParameterError { .. })));
        }
    }
    #[tokio::test]
    async fn limits_are_rejected_before_network_access() {
        for (size, seconds) in [(0, 5), (33, 5), (2, 0), (2, 61)] {
            assert!(PostgresConnectionPool::new_with_config(
                Config::new(),
                "disable",
                None,
                size,
                std::time::Duration::from_secs(seconds)
            )
            .await
            .is_err());
        }
    }
}
