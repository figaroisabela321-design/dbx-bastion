//! Bastion startup state and single-instance lock (TASK-005C-1).
//!
//! Startup states:
//! - `Ready`: all checks passed; bastion features may proceed as they
//!   are implemented (005C-2+).
//! - `Degraded`: the audit trail has untriaged interruptions. The
//!   process starts a limited management surface, but **all SQL
//!   execution is refused** until an operator triages the records.
//!   Degraded never becomes Ready on its own; triage is explicit.
//! - `StartupFailed`: returned as an `Err` from initialization — the
//!   process exits. Never falls back to legacy mode.
//!
//! Single-instance: the SQLite audit store plus in-memory in-flight
//! tracking is a single-process design. A file lock
//! (`bastion.lock` in the bastion data dir) guarantees at most one
//! bastion instance per audit database. The lock is held for the
//! lifetime of the process; a second instance fails fast with a clear
//! error.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dbx_bastion::audit::AuditService;
use fs2::FileExt;

/// Bastion startup state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupState {
    /// Fully operational.
    Ready,
    /// Audit has untriaged interruptions: management surface only,
    /// SQL execution refused.
    Degraded,
}

/// Shared bastion state for the web process.
pub struct BastionState {
    /// The bastion domain service (auth, assets, RBAC, audit, gateway).
    pub service: dbx_bastion::BastionService,
    /// DBX connection/execution state (connection registry, running
    /// queries, pools). Bastion never uses the legacy password auth or
    /// legacy routes; this is only the connection/execution substrate.
    pub dbx: Arc<dbx_core::connection::AppState>,
    /// Query gateway with the real DBX executor (005C-3/4). `None`
    /// until wired in `init`.
    pub gateway: Option<Arc<dbx_bastion::query::QueryGateway>>,
    /// Session cookie policy for this process.
    pub cookie_config: super::session::CookieConfig,
    /// Startup state decided during initialization.
    pub startup_state: StartupState,
    /// Held for the process lifetime; dropping releases the lock.
    _instance_lock: File,
    /// Directory holding `bastion.db` and `bastion.lock`.
    #[allow(dead_code)]
    pub dir: PathBuf,
}

impl BastionState {
    /// Asset service wired with the live DBX connection adapter.
    /// The adapter is constructed per call (cheap); it shares the
    /// `Arc<AppState>`.
    pub fn asset_service(&self) -> dbx_bastion::asset::AssetService {
        let adapter = Arc::new(super::adapters::WebDbxConnectionAdapter::new(self.dbx.clone()));
        self.service.asset_service(adapter)
    }

    /// Initialize bastion mode. Every failure is a startup failure —
    /// the caller must exit, never fall back to legacy mode.
    pub async fn init(dir: &Path, dbx: Arc<dbx_core::connection::AppState>) -> Result<Arc<Self>, String> {
        // 0. Data directory: create with 0700 when missing, then run
        //    the full filesystem security check (ownership, 0700,
        //    no symlinks, safe parent). Any violation is a startup
        //    failure — permissions are never repaired automatically.
        super::fs_security::create_dir_secure(dir)?;
        super::fs_security::check_data_dir_security(dir)?;

        // 1. Single-instance lock first: fail fast if another bastion
        //    instance owns this audit database.
        let lock_path = dir.join("bastion.lock");
        let lock_is_new = std::fs::symlink_metadata(&lock_path).is_err();
        let lock_file =
            OpenOptions::new().create(true).write(true).open(&lock_path).map_err(|e| {
                format!("bastion startup failed: cannot open instance lock {}: {e}", lock_path.display())
            })?;
        if lock_is_new {
            super::fs_security::secure_new_file(&lock_path, "instance lock")?;
        }
        super::fs_security::check_data_file_security(&lock_path, "instance lock")?;
        lock_file.try_lock_exclusive().map_err(|e| {
            format!(
                "bastion startup failed: another bastion instance holds {} ({e}); \
                 refusing to share the audit database",
                lock_path.display()
            )
        })?;

        // 2. Open the bastion store (runs migrations; failure is fatal).
        let db_path = dir.join("bastion.db");
        let db_is_new = std::fs::symlink_metadata(&db_path).is_err();
        let service = dbx_bastion::BastionService::open(&db_path)
            .map_err(|e| format!("bastion startup failed: cannot open bastion store {}: {e}", db_path.display()))?;
        if db_is_new {
            super::fs_security::secure_new_file(&db_path, "bastion database")?;
        }
        super::fs_security::check_data_file_security(&db_path, "bastion database")?;

        // 3. Check for untriaged audit interruptions. Any `started`
        //    or `unknown_interrupted` row means a previous execution
        //    has an unknown outcome: start degraded (management
        //    surface only, SQL execution refused) until an operator
        //    triages the records. Degraded still starts — otherwise a
        //    crash would make recovery impossible.
        let audit = dbx_bastion::audit::SqliteAuditService::new(service.store().clone());
        let has_interruptions = audit
            .has_untriaged_interruptions()
            .await
            .map_err(|e| format!("bastion startup failed: cannot check audit trail: {e}"))?;
        let startup_state = if has_interruptions { StartupState::Degraded } else { StartupState::Ready };
        if startup_state == StartupState::Degraded {
            tracing::warn!(
                "bastion audit trail has untriaged interruptions; starting DEGRADED: SQL execution refused until triage"
            );
        }

        let cookie_config = super::session::CookieConfig::from_env();

        // Wire the query gateway with the real DBX executor (005C-3/4).
        let store = service.store().clone();
        let clock: Arc<dyn dbx_bastion::auth::Clock> = Arc::new(dbx_bastion::auth::SystemClock);
        let audit = Arc::new(dbx_bastion::audit::SqliteAuditService::new(store.clone()));
        let executor = Arc::new(super::executor::DbxQueryExecutor::new(dbx.clone(), store.clone(), clock.clone()));
        let gateway = Arc::new(dbx_bastion::query::QueryGateway::new(store, clock, audit, executor));

        Ok(Arc::new(Self {
            service,
            dbx,
            gateway: Some(gateway),
            cookie_config,
            startup_state,
            _instance_lock: lock_file,
            dir: dir.to_path_buf(),
        }))
    }

    /// `true` when SQL execution must be refused (degraded startup).
    /// 005C-1 has no execution routes yet; 005C-4 wires this into the
    /// query gateway path.
    pub fn execution_refused(&self) -> bool {
        self.startup_state == StartupState::Degraded
    }
}
