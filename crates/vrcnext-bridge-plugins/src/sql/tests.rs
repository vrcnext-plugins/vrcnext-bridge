//! The `sql` service against a database made here, so the tests never touch VRCNext's own.
//!
//! Most of these are refusals: which databases exist, what a statement may be, and what a read may
//! not do. The happy path is checked against a seeded copy of `image_versions` shaped like the real
//! table, since that is the first thing this service exists to read.
//!
//! Every test returns a `Result` and reaches into an answer through [`field`] and [`row`] rather
//! than by indexing, so a malformed answer fails with the key it was looking for instead of a
//! panic from inside `serde_json`.

use serde_json::{Value, json};
use vrcnext_bridge_core::Service;

use super::{DATABASES, MAX_PARAMS, MAX_STATEMENT_MS, SqlService, single_statement};

type Fallible = Result<(), Box<dyn std::error::Error>>;
type Got<T> = Result<T, Box<dyn std::error::Error>>;

/// A temp directory holding a `VRCNData.db` shaped like the real one's `image_versions`.
struct Fixture {
    dir: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Got<Self> {
        let dir = std::env::temp_dir().join(format!(
            "vrcnext-sql-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir)?;
        let connection = rusqlite::Connection::open(dir.join("VRCNData.db"))?;
        connection.execute_batch(
            "CREATE TABLE image_versions (key TEXT PRIMARY KEY, url TEXT NOT NULL);
             INSERT INTO image_versions VALUES
               ('Users/usr_1', 'https://api.vrchat.cloud/api/1/image/file_a/1/800'),
               ('Users/usr_1_pfp', 'https://api.vrchat.cloud/api/1/image/file_b/1/800'),
               ('Avatars/avtr_1', 'https://api.vrchat.cloud/api/1/image/file_c/1/800');
             CREATE TABLE blobs (id INTEGER PRIMARY KEY, body BLOB);
             INSERT INTO blobs VALUES (1, x'00010203');",
        )?;
        Ok(Self { dir })
    }

    fn service(&self) -> SqlService {
        SqlService::new(self.dir.clone())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// One field of an object, or an error naming what was missing.
fn field<'a>(value: &'a Value, key: &str) -> Got<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| format!("no `{key}` in {value}").into())
}

/// One row of a `query` answer.
fn row(answer: &Value, index: usize) -> Got<&Value> {
    field(answer, "rows")?
        .as_array()
        .and_then(|rows| rows.get(index))
        .ok_or_else(|| format!("no row {index} in {answer}").into())
}

fn rows(answer: &Value) -> Got<usize> {
    field(answer, "rows")?
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| "rows is not an array".into())
}

fn query(service: &SqlService, params: Value) -> Result<Value, String> {
    service
        .call("query", params)
        .map_err(|error| error.to_string())
}

/// `SELECT count(*)` over the seeded table, as the check that a refusal changed nothing.
fn counted(service: &SqlService) -> Got<i64> {
    let answer = query(
        service,
        json!({ "database": "vrcnext", "sql": "SELECT count(*) AS n FROM image_versions" }),
    )
    .map_err(Box::<dyn std::error::Error>::from)?;
    field(row(&answer, 0)?, "n")?
        .as_i64()
        .ok_or_else(|| "n is not a number".into())
}

fn refusal(service: &SqlService, params: Value) -> Got<String> {
    match query(service, params) {
        Err(error) => Ok(error),
        Ok(answer) => Err(format!("expected a refusal, got {answer}").into()),
    }
}

#[test]
fn a_parameterised_lookup_answers_with_columns_and_rows() -> Fallible {
    let fixture = Fixture::new()?;
    let answer = query(
        &fixture.service(),
        json!({
            "database": "vrcnext",
            "sql": "SELECT key, url FROM image_versions WHERE key = ?1",
            "params": ["Avatars/avtr_1"],
        }),
    )?;
    assert_eq!(field(&answer, "columns")?, &json!(["key", "url"]));
    assert_eq!(rows(&answer)?, 1);
    assert_eq!(
        field(row(&answer, 0)?, "url")?,
        &json!("https://api.vrchat.cloud/api/1/image/file_c/1/800")
    );
    Ok(())
}

#[test]
fn a_parameter_is_bound_and_cannot_become_sql() -> Fallible {
    let fixture = Fixture::new()?;
    let service = fixture.service();
    // The classic shape. Bound, it is a key that does not exist, not a second statement.
    let answer = query(
        &service,
        json!({
            "database": "vrcnext",
            "sql": "SELECT url FROM image_versions WHERE key = ?1",
            "params": ["x' OR '1'='1"],
        }),
    )?;
    assert_eq!(rows(&answer)?, 0, "it matched nothing, as a key");
    assert_eq!(counted(&service)?, 3, "and the table is untouched");
    Ok(())
}

#[test]
fn a_second_statement_is_refused_rather_than_silently_dropped() -> Fallible {
    let fixture = Fixture::new()?;
    let service = fixture.service();
    let error = refusal(
        &service,
        json!({ "database": "vrcnext", "sql": "SELECT 1; DROP TABLE image_versions" }),
    )?;
    assert!(error.contains("one statement per call"), "{error}");
    assert_eq!(counted(&service)?, 3, "nothing was dropped");
    Ok(())
}

#[test]
fn a_semicolon_inside_a_literal_or_a_comment_is_not_a_second_statement() {
    assert!(single_statement("SELECT 'a;b'"));
    assert!(single_statement("SELECT \"a;b\""));
    assert!(single_statement("SELECT [a;b]"));
    assert!(single_statement("SELECT 1 -- and; then\n"));
    assert!(single_statement("SELECT /* a; b */ 1"));
    assert!(
        single_statement("SELECT 1;"),
        "a trailing semicolon is fine"
    );
    assert!(single_statement("SELECT 1;   \n  "));
    assert!(!single_statement("SELECT 1; SELECT 2"));
    assert!(!single_statement("SELECT 'a;b'; DROP TABLE t"));
    assert!(!single_statement("SELECT 1 -- c\n; DROP TABLE t"));
}

#[test]
fn a_read_cannot_write_even_when_the_statement_asks_to() -> Fallible {
    let fixture = Fixture::new()?;
    let service = fixture.service();
    let error = refusal(
        &service,
        json!({ "database": "vrcnext", "sql": "DELETE FROM image_versions" }),
    )?;
    assert!(
        error.contains("sqlite refused the statement"),
        "a write asked of a read is the caller's mistake, not the bridge's: {error}"
    );
    assert!(error.contains("readonly"), "{error}");
    assert_eq!(counted(&service)?, 3);
    Ok(())
}

#[test]
fn a_statement_cannot_attach_a_second_database() -> Fallible {
    let fixture = Fixture::new()?;
    let service = fixture.service();
    // A file the alias does not name, which ATTACH would otherwise open.
    let other = fixture.dir.join("other.db");
    rusqlite::Connection::open(&other)?.execute_batch("CREATE TABLE secret (x TEXT);")?;
    for sql in [
        format!("ATTACH DATABASE '{}' AS o", other.display()),
        format!("ATTACH DATABASE 'file:{}?mode=ro' AS o", other.display()),
    ] {
        let error = refusal(&service, json!({ "database": "vrcnext", "sql": sql }))?;
        assert!(error.contains("sqlite refused the statement"), "{error}");
    }
    assert_eq!(counted(&service)?, 3);
    Ok(())
}

#[test]
fn vrcnexts_own_database_refuses_execute_before_it_opens_anything() -> Fallible {
    let fixture = Fixture::new()?;
    let error = match fixture.service().call(
        "execute",
        json!({ "database": "vrcnext", "sql": "DELETE FROM image_versions" }),
    ) {
        Err(error) => error.to_string(),
        Ok(answer) => return Err(format!("expected a refusal, got {answer}").into()),
    };
    assert!(error.contains("read-only"), "{error}");
    Ok(())
}

#[test]
fn a_caller_names_an_alias_and_never_a_path() -> Fallible {
    let fixture = Fixture::new()?;
    let service = fixture.service();
    for attempt in [
        "../../../../etc/passwd",
        "/etc/passwd",
        "VRCNData.db",
        "vrcnext/../avatars",
        "",
    ] {
        let error = refusal(&service, json!({ "database": attempt, "sql": "SELECT 1" }))?;
        assert!(
            error.contains("unknown database"),
            "`{attempt}` should not resolve: {error}"
        );
    }
    Ok(())
}

#[test]
fn a_missing_file_says_so_instead_of_being_created() -> Fallible {
    let fixture = Fixture::new()?;
    // `avatars` is registered but this fixture has no AvatarDB/Avatars.db.
    let error = refusal(
        &fixture.service(),
        json!({ "database": "avatars", "sql": "SELECT 1" }),
    )?;
    assert!(error.contains("not on this machine yet"), "{error}");
    assert!(
        !fixture.dir.join("AvatarDB/Avatars.db").exists(),
        "a query must never bring a database into being"
    );
    Ok(())
}

#[test]
fn too_many_parameters_is_refused() -> Fallible {
    let fixture = Fixture::new()?;
    let params: Vec<Value> = (0..=MAX_PARAMS).map(|n| json!(n)).collect();
    let error = refusal(
        &fixture.service(),
        json!({ "database": "vrcnext", "sql": "SELECT 1", "params": params }),
    )?;
    assert!(error.contains("at most"), "{error}");
    Ok(())
}

#[test]
fn a_structured_parameter_is_refused_rather_than_stringified() -> Fallible {
    let fixture = Fixture::new()?;
    let error = refusal(
        &fixture.service(),
        json!({ "database": "vrcnext", "sql": "SELECT ?1 AS v", "params": [{ "a": 1 }] }),
    )?;
    assert!(error.contains("string, number, boolean or null"), "{error}");
    Ok(())
}

#[test]
fn a_blob_comes_back_as_its_length_not_its_bytes() -> Fallible {
    let fixture = Fixture::new()?;
    let answer = query(
        &fixture.service(),
        json!({ "database": "vrcnext", "sql": "SELECT body FROM blobs WHERE id = 1" }),
    )?;
    assert_eq!(
        field(row(&answer, 0)?, "body")?,
        &json!({ "blobBytes": 4 }),
        "a caller wanting bytes wants a different method than this one"
    );
    Ok(())
}

#[test]
fn describe_publishes_the_rules_and_every_alias() -> Fallible {
    let fixture = Fixture::new()?;
    let described = fixture.service().describe();
    let listed = field(&described, "databases")?
        .as_array()
        .ok_or("databases is not an array")?
        .iter()
        .filter_map(|db| db.get("alias").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        DATABASES.iter().map(|db| db.alias).collect::<Vec<_>>()
    );
    assert!(
        DATABASES.iter().all(|db| !db.writable),
        "nothing VRCNext owns is writable; a writable alias must be a database we own"
    );
    for key in ["paths", "statements", "reads", "blobs"] {
        assert!(
            field(&described, key)?.is_string(),
            "describe should state {key}"
        );
    }
    Ok(())
}

#[test]
fn an_unknown_method_is_refused() -> Fallible {
    let fixture = Fixture::new()?;
    let error = match fixture.service().call("drop", json!({})) {
        Err(error) => error.to_string(),
        Ok(answer) => return Err(format!("expected a refusal, got {answer}").into()),
    };
    assert!(error.contains("drop"), "{error}");
    Ok(())
}

#[test]
fn a_statement_that_will_not_finish_is_interrupted_rather_than_left_running() -> Fallible {
    let fixture = Fixture::new()?;
    // A recursive CTE with no bound: it would produce rows until something stopped it, and MAX_ROWS
    // is not that something — it caps what comes back, not what SQLite scans. The watchdog is.
    let started = std::time::Instant::now();
    let error = refusal(
        &fixture.service(),
        json!({
            "database": "vrcnext",
            "sql": "WITH RECURSIVE forever(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM forever) \
                    SELECT count(*) AS n FROM forever",
        }),
    )?;
    let waited = started.elapsed();
    assert!(
        error.contains("interrupted") || error.contains("too many rows"),
        "it must end by the interrupt or the row cap, not by running out of memory: {error}"
    );
    assert!(
        waited < std::time::Duration::from_millis(super::MAX_STATEMENT_MS + 5_000),
        "it should have been stopped near the deadline, not {waited:?}"
    );
    Ok(())
}

#[test]
fn the_watchdog_lets_a_finished_statement_go_without_waiting_out_its_deadline() -> Fallible {
    let fixture = Fixture::new()?;
    let started = std::time::Instant::now();
    for _ in 0..5 {
        let _ = counted(&fixture.service())?;
    }
    let waited = started.elapsed();
    assert!(
        waited < std::time::Duration::from_millis(MAX_STATEMENT_MS),
        "five quick queries must not each pay the deadline: {waited:?}"
    );
    Ok(())
}
