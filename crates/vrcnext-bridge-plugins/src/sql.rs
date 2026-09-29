//! `SQLite` for plugins, over the bridge.
//!
//! The page has no filesystem, so the databases VRCNext keeps beside its settings — the join
//! history, the world and avatar tracking, the table that remembers which public URL each cached
//! picture came from — are unreadable from a plugin. This service reads them, and writes to the
//! ones a plugin is allowed to write.
//!
//! # What keeps this from being a file-read primitive
//!
//! A plugin never names a path. It names an **alias** from [`DATABASES`], and the bridge owns the
//! path that alias resolves to. There is no traversal to defend against, no way to discover what
//! else is on disk, and no way to reach a database this service does not already know about.
//!
//! Statements are prepared and their parameters **bound**, never interpolated, so there is no
//! string-building path for a caller's value to escape. One statement per call: `SQLite` parses the
//! first and leaves the rest, so a trailing statement is detected and refused rather than silently
//! dropped — `DELETE FROM x; DROP TABLE y` does neither thing.
//!
//! Read and write are separate methods over separate connections. A read opens the file
//! `SQLITE_OPEN_READ_ONLY` *and* sets `query_only`, so a statement that got past the parse checks
//! still cannot write.
//!
//! An alias is only a boundary if a statement cannot name a second file itself. `ATTACH
//! DATABASE '/any/path' AS x` would do exactly that, so every connection is opened with the
//! attached-database limit at zero (and without URI filenames), and `ATTACH` fails whatever it
//! names.
//!
//! # Sharing the file with VRCNext
//!
//! VRCNext holds these databases open and writes to them while the bridge reads. That is safe in
//! WAL mode, which is what VRCNext uses: readers do not block the writer and see a consistent
//! snapshot. Writes take `busy_timeout` and an immediate transaction so two writers queue instead
//! of failing, but a plugin writing to VRCNext's own database is writing to a schema nobody
//! documented and which VRCNext also caches in memory — see [`Database::writable`].

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vrcnext_bridge_core::{Service, ServiceError};

/// Most rows one query may return.
pub const MAX_ROWS: usize = 10_000;

/// Largest result one query may produce, as serialised JSON.
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// Most parameters one statement may bind.
pub const MAX_PARAMS: usize = 64;

/// How long a statement may run before it is interrupted.
pub const MAX_STATEMENT_MS: u64 = 5_000;

/// How long a write waits for VRCNext to finish its own transaction.
pub const BUSY_TIMEOUT_MS: u64 = 3_000;

/// A database this service will open, and what a plugin may do to it.
#[derive(Debug, Clone, Copy)]
pub struct Database {
    /// What a plugin calls it. The only name that crosses the wire.
    pub alias: &'static str,
    /// The file, relative to VRCNext's configuration directory.
    pub file: &'static str,
    /// Whether `execute` is allowed here at all.
    ///
    /// False for everything VRCNext owns. The schema is undocumented and unversioned, and VRCNext
    /// keeps rows cached in memory, so a row a plugin changes can be overwritten without warning
    /// or leave VRCNext's own copy disagreeing with the file. Reading is safe and useful; writing
    /// is a corruption report waiting to be filed against the wrong project. A plugin that wants
    /// durable storage of its own has `state`, and a database of its own can be added here with
    /// `writable: true`.
    pub writable: bool,
    /// Said out loud in `describe`, so the page can explain a refusal without guessing.
    pub about: &'static str,
}

/// Every database a plugin may name.
pub const DATABASES: &[Database] = &[
    Database {
        alias: "vrcnext",
        file: "VRCNData.db",
        writable: false,
        about: "VRCNext's own records: join history, world and avatar tracking, user memos, and image_versions, which maps each cached picture to the public URL it came from",
    },
    Database {
        alias: "avatars",
        file: "AvatarDB/Avatars.db",
        writable: false,
        about: "VRCNext's avatar database",
    },
];

/// Everything that can go wrong, as the page will see it.
#[derive(Debug, thiserror::Error)]
pub enum SqlError {
    /// The parameters were not the shape this service takes.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// No database is registered under that alias.
    #[error("unknown database `{0}`; this bridge serves {known}", known = aliases())]
    UnknownDatabase(String),
    /// The alias exists but is read-only.
    #[error("`{0}` is read-only: it is VRCNext's own database, whose schema is not ours to change")]
    ReadOnly(String),
    /// The file is not there, which usually means VRCNext has not made it yet.
    #[error("`{0}` is not on this machine yet")]
    Missing(String),
    /// More than one statement in one call.
    #[error("one statement per call; this call carried more than one")]
    ManyStatements,
    /// Too many bound parameters.
    #[error("a statement may bind at most {MAX_PARAMS} parameters")]
    ManyParams,
    /// The result was larger than [`MAX_ROWS`] or [`MAX_RESULT_BYTES`].
    #[error("the result is larger than this service returns ({0}); narrow the query")]
    TooLarge(&'static str),
    /// The statement is not one `SQLite` would run here: a syntax error, an unknown table, or a
    /// write asked of a read. All the caller's to fix, which is why it is not [`Self::Sqlite`].
    #[error("sqlite refused the statement: {0}")]
    Refused(String),
    /// `SQLite` failed for a reason that is not the caller's fault.
    #[error("sqlite: {0}")]
    Sqlite(String),
}

impl From<SqlError> for ServiceError {
    fn from(error: SqlError) -> Self {
        let message = error.to_string();
        match error {
            // The caller asked for something it may not have, or wrote it wrongly. All fixable
            // by changing the request, which is what a 400 tells the page.
            SqlError::BadRequest(_)
            | SqlError::UnknownDatabase(_)
            | SqlError::ReadOnly(_)
            | SqlError::ManyStatements
            | SqlError::ManyParams
            | SqlError::TooLarge(_)
            | SqlError::Refused(_) => Self::BadRequest(message),
            // The database is simply not on this machine yet. Nothing is wrong with the request,
            // and the same call may work later, which is what 503 means here.
            SqlError::Missing(_) => Self::Unavailable(message),
            SqlError::Sqlite(_) => Self::Internal(message),
        }
    }
}

fn aliases() -> String {
    DATABASES
        .iter()
        .map(|db| db.alias)
        .collect::<Vec<_>>()
        .join(", ")
}

fn find(alias: &str) -> Result<&'static Database, SqlError> {
    DATABASES
        .iter()
        .find(|db| db.alias == alias)
        .ok_or_else(|| SqlError::UnknownDatabase(alias.to_owned()))
}

/// One query or statement, as the page describes it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    /// An alias from [`DATABASES`], never a path.
    database: String,
    sql: String,
    /// Values bound to the statement's placeholders, in order.
    #[serde(default)]
    params: Vec<Value>,
}

/// `SQLite` for plugins: read VRCNext's databases, write the ones that are ours.
#[derive(Debug, Default)]
pub struct SqlService {
    root: PathBuf,
}

impl SqlService {
    /// A service reading the databases under `root`, VRCNext's configuration directory.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, db: &Database) -> Result<PathBuf, SqlError> {
        let path = self.root.join(db.file);
        if path.is_file() {
            Ok(path)
        } else {
            Err(SqlError::Missing(db.alias.to_owned()))
        }
    }

    fn query(&self, params: Value) -> Result<Value, SqlError> {
        let request = parse(params)?;
        let db = find(&request.database)?;
        let connection = self.open(db, Access::Read)?;
        run(&connection, &request, Access::Read)
    }

    fn execute(&self, params: Value) -> Result<Value, SqlError> {
        let request = parse(params)?;
        let db = find(&request.database)?;
        if !db.writable {
            return Err(SqlError::ReadOnly(db.alias.to_owned()));
        }
        let connection = self.open(db, Access::Write)?;
        run(&connection, &request, Access::Write)
    }

    fn open(&self, db: &Database, access: Access) -> Result<Connection, SqlError> {
        let path = self.path(db)?;
        let flags = match access {
            // No `CREATE`: this service never brings a database into being, so a typo in a
            // registered path fails loudly instead of serving an empty file.
            Access::Read => OpenFlags::SQLITE_OPEN_READ_ONLY,
            Access::Write => OpenFlags::SQLITE_OPEN_READ_WRITE,
        };
        let connection =
            Connection::open_with_flags(&path, flags).map_err(|error| sqlite(&error))?;
        // No second database, ever: see the module docs.
        connection
            .set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(|error| sqlite(&error))?;
        connection
            .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(|error| sqlite(&error))?;
        if access == Access::Read {
            // Belt and braces: the file is already open read-only, and this refuses a write at
            // the statement level too, so the two would have to fail together to let one through.
            connection
                .pragma_update(None, "query_only", true)
                .map_err(|error| sqlite(&error))?;
        }
        Ok(connection)
    }
}

/// Which of the two methods is running, since they share the plumbing but not the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

/// A `SQLite` failure, split by whose fault it is.
///
/// Anything `SQLite` decided about the statement — bad syntax, no such table, a write on a
/// read-only connection — is the caller's to fix and comes back as a refusal. Everything else (a
/// locked file, a disk error) is ours, and is reported as one.
fn sqlite(error: &rusqlite::Error) -> SqlError {
    let blames_the_caller = matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ffi::ErrorCode::ReadOnly
                    | rusqlite::ffi::ErrorCode::Unknown
                    | rusqlite::ffi::ErrorCode::ConstraintViolation
                    | rusqlite::ffi::ErrorCode::TypeMismatch
                    | rusqlite::ffi::ErrorCode::OperationInterrupted,
                ..
            },
            _,
        ) | rusqlite::Error::InvalidParameterCount(..)
            | rusqlite::Error::InvalidColumnName(_)
    );
    if blames_the_caller {
        SqlError::Refused(error.to_string())
    } else {
        SqlError::Sqlite(error.to_string())
    }
}

fn parse(params: Value) -> Result<Request, SqlError> {
    let request: Request =
        serde_json::from_value(params).map_err(|error| SqlError::BadRequest(error.to_string()))?;
    if request.params.len() > MAX_PARAMS {
        return Err(SqlError::ManyParams);
    }
    Ok(request)
}

/// A JSON value as something `SQLite` can bind. Anything structured is refused rather than
/// stringified, since a caller who passed an object meant something this cannot express.
fn bind(value: &Value) -> Result<SqlValue, SqlError> {
    match value {
        Value::Null => Ok(SqlValue::Null),
        Value::Bool(flag) => Ok(SqlValue::Integer(i64::from(*flag))),
        Value::String(text) => Ok(SqlValue::Text(text.clone())),
        Value::Number(number) => number
            .as_i64()
            .map(SqlValue::Integer)
            .or_else(|| number.as_f64().map(SqlValue::Real))
            .ok_or_else(|| SqlError::BadRequest(format!("{number} is not a number SQLite takes"))),
        Value::Array(_) | Value::Object(_) => Err(SqlError::BadRequest(
            "a parameter must be a string, number, boolean or null".to_owned(),
        )),
    }
}

/// A column as JSON. Blobs come back as their length rather than their bytes: this service
/// answers in JSON, and a caller wanting bytes wants a different method than this one.
fn column(value: &ValueRef<'_>) -> Value {
    match *value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => json!(number),
        ValueRef::Real(number) => json!(number),
        ValueRef::Text(bytes) => json!(String::from_utf8_lossy(bytes)),
        ValueRef::Blob(bytes) => json!({ "blobBytes": bytes.len() }),
    }
}

/// Whether `sql` holds exactly one statement.
///
/// `sqlite3_prepare_v2` compiles the first statement and hands back the rest, and rusqlite does
/// not expose that tail — so a second statement would be silently dropped rather than run, which
/// is safe but confusing. This finds it instead, by looking for a `;` with anything but whitespace
/// after it, ignoring the ones inside string and identifier literals and inside comments, where a
/// semicolon is just a character.
fn single_statement(sql: &str) -> bool {
    let mut rest = sql.chars().peekable();
    let mut seen_end = false;
    while let Some(ch) = rest.next() {
        match ch {
            '\'' | '"' | '`' => {
                // A quoted literal, ending at the next matching quote; SQLite escapes a quote by
                // doubling it, which this handles by simply closing and reopening.
                for inner in rest.by_ref() {
                    if inner == ch {
                        break;
                    }
                }
            }
            '[' => {
                for inner in rest.by_ref() {
                    if inner == ']' {
                        break;
                    }
                }
            }
            '-' if rest.peek() == Some(&'-') => {
                for inner in rest.by_ref() {
                    if inner == '\n' {
                        break;
                    }
                }
            }
            '/' if rest.peek() == Some(&'*') => {
                rest.next();
                let mut last = ' ';
                for inner in rest.by_ref() {
                    if last == '*' && inner == '/' {
                        break;
                    }
                    last = inner;
                }
            }
            ';' => seen_end = true,
            _ if ch.is_whitespace() => {}
            // Anything else after a `;` starts a second statement.
            _ if seen_end => return false,
            _ => {}
        }
    }
    true
}

/// Interrupts `connection` if it is still working after [`MAX_STATEMENT_MS`].
///
/// A query nobody bounded can pin a core for as long as `SQLite` takes — `MAX_ROWS` caps what comes
/// back, not what is scanned, and a join over the 21 000-row image table finds that out the slow
/// way. `SQLite`'s own interrupt is the only thing that stops a statement mid-scan; it makes the
/// running call return `SQLITE_INTERRUPT`, which surfaces as an ordinary error.
///
/// Dropping the returned guard cancels the watchdog, so a fast query pays for a parked thread and
/// nothing more.
struct Watchdog {
    done: Arc<AtomicBool>,
}

impl Watchdog {
    fn arm(connection: &Connection) -> Self {
        let handle = connection.get_interrupt_handle();
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        std::thread::spawn(move || {
            // Woken in slices so a finished statement is noticed promptly rather than after the
            // whole deadline, which is what makes the thread short-lived in the common case.
            let slice = Duration::from_millis(50);
            let mut waited = Duration::ZERO;
            let limit = Duration::from_millis(MAX_STATEMENT_MS);
            while waited < limit {
                if flag.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(slice);
                waited = waited.saturating_add(slice);
            }
            if !flag.load(Ordering::Relaxed) {
                handle.interrupt();
            }
        });
        Self { done }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
    }
}

fn run(connection: &Connection, request: &Request, access: Access) -> Result<Value, SqlError> {
    if !single_statement(&request.sql) {
        return Err(SqlError::ManyStatements);
    }
    let _watchdog = Watchdog::arm(connection);
    let mut statement = connection
        .prepare(&request.sql)
        .map_err(|error| sqlite(&error))?;
    let bound = request
        .params
        .iter()
        .map(bind)
        .collect::<Result<Vec<_>, _>>()?;
    let references: Vec<&dyn rusqlite::ToSql> = bound
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();

    if access == Access::Write {
        let changed = statement
            .execute(references.as_slice())
            .map_err(|error| sqlite(&error))?;
        return Ok(json!({
            "changed": changed,
            "lastInsertRowid": connection.last_insert_rowid(),
        }));
    }

    let names: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut rows = statement
        .query(references.as_slice())
        .map_err(|error| sqlite(&error))?;
    let mut out: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next().map_err(|error| sqlite(&error))? {
        if out.len() >= MAX_ROWS {
            return Err(SqlError::TooLarge("too many rows"));
        }
        let mut record = Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = column(&row.get_ref(index).map_err(|error| sqlite(&error))?);
            bytes = bytes
                .saturating_add(name.len())
                .saturating_add(estimate(&value));
            record.insert(name.clone(), value);
        }
        if bytes > MAX_RESULT_BYTES {
            return Err(SqlError::TooLarge("too many bytes"));
        }
        out.push(Value::Object(record));
    }
    Ok(json!({ "columns": names, "rows": out }))
}

/// Roughly how much JSON a value will take, counted as rows are read so an oversized result is
/// refused before it is all in memory rather than after.
fn estimate(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(_) => 5,
        Value::Number(_) => 20,
        Value::String(text) => text.len().saturating_add(2),
        Value::Array(_) | Value::Object(_) => 32,
    }
}

impl Service for SqlService {
    fn name(&self) -> &'static str {
        "sql"
    }

    fn summary(&self) -> &'static str {
        "Read VRCNext's SQLite databases, and write the ones that are not VRCNext's"
    }

    fn describe(&self) -> Value {
        json!({
            "methods": ["query", "execute", "databases"],
            "databases": DATABASES.iter().map(|db| json!({
                "alias": db.alias,
                "writable": db.writable,
                "about": db.about,
            })).collect::<Vec<_>>(),
            "maxRows": MAX_ROWS,
            "maxResultBytes": MAX_RESULT_BYTES,
            "maxParams": MAX_PARAMS,
            "maxStatementMs": MAX_STATEMENT_MS,
            "paths": "a caller names a registered alias, never a path; the bridge owns which file each alias is",
            "statements": "one statement per call, prepared with its parameters bound — never interpolated; a trailing statement is refused",
            "reads": "opened SQLITE_OPEN_READ_ONLY with query_only set, so a read cannot write even if the statement asks to",
            "blobs": "returned as {blobBytes: n}, not as bytes",
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "query" => Ok(self.query(params)?),
            "execute" => Ok(self.execute(params)?),
            "databases" => Ok(self.describe()),
            other => Err(ServiceError::UnknownMethod {
                service: "sql",
                method: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
