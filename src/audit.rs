//! Audit log and analytics (SQLite). Stores request metadata only: who, which model,
//! the policy decision, token usage, cost and latency. No secrets, no prompt bodies.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::pricing::Usage;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RequestRecord {
    pub id: String,
    pub ts: String,
    pub client_id: String,
    pub client_name: String,
    pub agent: String,
    pub project: String,
    pub endpoint: String,
    pub model_alias: String,
    pub provider_id: String,
    pub provider_name: String,
    pub upstream_model: String,
    /// "allowed" | "denied"
    pub decision: String,
    pub decision_reason: String,
    /// "rule" | "session" | "once" | "auto" | "denied" | "timeout" | ""
    pub consent: String,
    pub status: u16,
    pub error: String,
    pub latency_ms: u64,
    pub usage: Usage,
    pub cost: f64,
    pub currency: String,
    pub price_id: String,
    pub cost_estimated: bool,
    pub stream: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub days: u32,
    pub provider: String,
    pub model: String,
    pub client: String,
    /// "" | "ok" | "error" | "denied"
    pub status: String,
    pub search: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Bucket {
    pub label: String,
    pub calls: u64,
    pub tokens: u64,
    pub cost: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DayPoint {
    pub day: String,
    pub calls: u64,
    pub cost: f64,
    pub tokens: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub calls: u64,
    pub ok: u64,
    pub errors: u64,
    pub denied: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cost: f64,
    pub estimated_cost: f64,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: u64,
    pub by_provider: Vec<Bucket>,
    pub by_model: Vec<Bucket>,
    pub by_client: Vec<Bucket>,
    pub by_agent: Vec<Bucket>,
    pub daily: Vec<DayPoint>,
}

pub struct Audit {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, day TEXT NOT NULL,
  client_id TEXT, client_name TEXT, agent TEXT, project TEXT, endpoint TEXT,
  model_alias TEXT, provider_id TEXT, provider_name TEXT, upstream_model TEXT,
  decision TEXT, decision_reason TEXT, consent TEXT,
  status INTEGER, error TEXT, latency_ms INTEGER,
  input INTEGER, output INTEGER, cache_read INTEGER, cache_write INTEGER, reasoning INTEGER,
  usage_source TEXT, cost REAL, currency TEXT, price_id TEXT, cost_estimated INTEGER, stream INTEGER
);
CREATE INDEX IF NOT EXISTS idx_requests_day ON requests(day);
CREATE INDEX IF NOT EXISTS idx_requests_client ON requests(client_id, day);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL
);
"#;

impl Audit {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Audit { conn: Mutex::new(conn) })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Audit { conn: Mutex::new(conn) })
    }

    pub fn record(&self, r: &RequestRecord) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO requests VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29)",
            params![
                r.id,
                r.ts,
                r.ts.get(..10).unwrap_or(""),
                r.client_id,
                r.client_name,
                r.agent,
                r.project,
                r.endpoint,
                r.model_alias,
                r.provider_id,
                r.provider_name,
                r.upstream_model,
                r.decision,
                r.decision_reason,
                r.consent,
                r.status,
                r.error,
                r.latency_ms as i64,
                r.usage.input as i64,
                r.usage.output as i64,
                r.usage.cache_read as i64,
                r.usage.cache_write as i64,
                r.usage.reasoning as i64,
                r.usage.source.as_str(),
                r.cost,
                r.currency,
                r.price_id,
                r.cost_estimated as i64,
                r.stream as i64
            ],
        )?;
        Ok(())
    }

    pub fn event(&self, kind: &str, message: &str) {
        let c = self.conn.lock().unwrap();
        let _ = c.execute("INSERT INTO events (ts, kind, message) VALUES (?1, ?2, ?3)", params![crate::config::now_rfc3339(), kind, message]);
    }

    pub fn events(&self, limit: u32) -> Vec<(String, String, String)> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT ts, kind, message FROM events ORDER BY id DESC LIMIT ?1").unwrap();
        st.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(|r| r.ok()).collect()
    }

    /// Spend of a client since `since_day` (inclusive), per currency.
    pub fn client_spend(&self, client_id: &str, since_day: &str) -> HashMap<String, f64> {
        let c = self.conn.lock().unwrap();
        let mut st = c
            .prepare("SELECT currency, SUM(cost) FROM requests WHERE client_id=?1 AND day>=?2 AND currency<>'' GROUP BY currency")
            .unwrap();
        st.query_map(params![client_id, since_day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn last_used(&self, client_id: &str) -> Option<String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT MAX(ts) FROM requests WHERE client_id=?1", [client_id], |r| r.get::<_, Option<String>>(0)).optional().ok().flatten().flatten()
    }

    fn where_clause(f: &Filter) -> (String, Vec<String>) {
        let mut w = vec!["1=1".to_string()];
        let mut p: Vec<String> = Vec::new();
        if f.days > 0 {
            let since = (chrono::Utc::now() - chrono::Duration::days(f.days as i64 - 1)).format("%Y-%m-%d").to_string();
            p.push(since);
            w.push(format!("day >= ?{}", p.len()));
        }
        for (col, val) in [("provider_name", &f.provider), ("model_alias", &f.model), ("client_name", &f.client)] {
            if !val.is_empty() {
                p.push(val.clone());
                w.push(format!("{col} = ?{}", p.len()));
            }
        }
        match f.status.as_str() {
            "ok" => w.push("decision='allowed' AND status BETWEEN 200 AND 299".into()),
            "error" => w.push("decision='allowed' AND (status < 200 OR status > 299)".into()),
            "denied" => w.push("decision='denied'".into()),
            _ => {}
        }
        if !f.search.is_empty() {
            p.push(format!("%{}%", f.search));
            let n = p.len();
            w.push(format!("(agent LIKE ?{n} OR client_name LIKE ?{n} OR model_alias LIKE ?{n} OR error LIKE ?{n} OR project LIKE ?{n})"));
        }
        (w.join(" AND "), p)
    }

    /// Analytics for the dashboard. `fx` converts a currency to the display currency.
    pub fn summary(&self, f: &Filter, fx: &dyn Fn(&str) -> f64) -> Summary {
        let c = self.conn.lock().unwrap();
        let (w, p) = Self::where_clause(f);
        let mut s = Summary::default();
        let params = rusqlite::params_from_iter(p.iter());

        let sql = format!(
            "SELECT decision, status, input, output, cache_read, cost, currency, cost_estimated, latency_ms, provider_name, model_alias, client_name, agent, day FROM requests WHERE {w}"
        );
        let mut st = c.prepare(&sql).unwrap();
        let mut lat: Vec<u64> = Vec::new();
        let mut prov: HashMap<String, Bucket> = HashMap::new();
        let mut model: HashMap<String, Bucket> = HashMap::new();
        let mut client: HashMap<String, Bucket> = HashMap::new();
        let mut agent: HashMap<String, Bucket> = HashMap::new();
        let mut daily: HashMap<String, DayPoint> = HashMap::new();
        let rows = st
            .query_map(params, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, f64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                ))
            })
            .unwrap();
        for row in rows.flatten() {
            let (decision, status, input, output, cache_read, cost, cur, est, latency, pn, ma, cn, ag, day) = row;
            s.calls += 1;
            if decision == "denied" {
                s.denied += 1;
            } else if (200..300).contains(&status) {
                s.ok += 1;
            } else {
                s.errors += 1;
            }
            let cost = cost * fx(&cur);
            let tokens = (input + output) as u64;
            s.input += input as u64;
            s.output += output as u64;
            s.cache_read += cache_read as u64;
            s.cost += cost;
            if est != 0 {
                s.estimated_cost += cost;
            }
            if decision == "allowed" {
                lat.push(latency as u64);
            }
            for (map, key) in [(&mut prov, pn), (&mut model, ma), (&mut client, cn), (&mut agent, if ag.is_empty() { "(unnamed)".into() } else { ag })] {
                if key.is_empty() {
                    continue;
                }
                let b = map.entry(key.clone()).or_insert_with(|| Bucket { label: key, ..Default::default() });
                b.calls += 1;
                b.tokens += tokens;
                b.cost += cost;
            }
            let d = daily.entry(day.clone()).or_insert_with(|| DayPoint { day, ..Default::default() });
            d.calls += 1;
            d.cost += cost;
            d.tokens += tokens;
        }
        if !lat.is_empty() {
            s.avg_latency_ms = lat.iter().sum::<u64>() as f64 / lat.len() as f64;
            lat.sort_unstable();
            s.p95_latency_ms = lat[((lat.len() as f64 * 0.95).ceil() as usize).saturating_sub(1).min(lat.len() - 1)];
        }
        let sorted = |m: HashMap<String, Bucket>| {
            let mut v: Vec<Bucket> = m.into_values().collect();
            v.sort_by(|a, b| b.cost.partial_cmp(&a.cost).unwrap().then(b.calls.cmp(&a.calls)));
            v
        };
        s.by_provider = sorted(prov);
        s.by_model = sorted(model);
        s.by_client = sorted(client);
        s.by_agent = sorted(agent);
        // continuous daily series
        if f.days > 0 {
            for i in (0..f.days as i64).rev() {
                let day = (chrono::Utc::now() - chrono::Duration::days(i)).format("%Y-%m-%d").to_string();
                s.daily.push(daily.remove(&day).unwrap_or(DayPoint { day, ..Default::default() }));
            }
        } else {
            let mut v: Vec<DayPoint> = daily.into_values().collect();
            v.sort_by(|a, b| a.day.cmp(&b.day));
            s.daily = v;
        }
        s
    }

    pub fn requests(&self, f: &Filter, limit: u32) -> Vec<RequestRecord> {
        let c = self.conn.lock().unwrap();
        let (w, p) = Self::where_clause(f);
        let sql = format!(
            "SELECT id, ts, client_id, client_name, agent, project, endpoint, model_alias, provider_id, provider_name, upstream_model, decision, decision_reason, consent, status, error, latency_ms, input, output, cache_read, cache_write, reasoning, usage_source, cost, currency, price_id, cost_estimated, stream FROM requests WHERE {w} ORDER BY ts DESC LIMIT {limit}"
        );
        let mut st = c.prepare(&sql).unwrap();
        st.query_map(rusqlite::params_from_iter(p.iter()), |r| {
            let src: String = r.get(22)?;
            Ok(RequestRecord {
                id: r.get(0)?,
                ts: r.get(1)?,
                client_id: r.get(2)?,
                client_name: r.get(3)?,
                agent: r.get(4)?,
                project: r.get(5)?,
                endpoint: r.get(6)?,
                model_alias: r.get(7)?,
                provider_id: r.get(8)?,
                provider_name: r.get(9)?,
                upstream_model: r.get(10)?,
                decision: r.get(11)?,
                decision_reason: r.get(12)?,
                consent: r.get(13)?,
                status: r.get::<_, i64>(14)? as u16,
                error: r.get(15)?,
                latency_ms: r.get::<_, i64>(16)? as u64,
                usage: Usage {
                    input: r.get::<_, i64>(17)? as u64,
                    output: r.get::<_, i64>(18)? as u64,
                    cache_read: r.get::<_, i64>(19)? as u64,
                    cache_write: r.get::<_, i64>(20)? as u64,
                    reasoning: r.get::<_, i64>(21)? as u64,
                    source: match src.as_str() {
                        "reported" => crate::pricing::UsageSource::Reported,
                        "estimated" => crate::pricing::UsageSource::Estimated,
                        _ => crate::pricing::UsageSource::Unavailable,
                    },
                },
                cost: r.get(23)?,
                currency: r.get(24)?,
                price_id: r.get(25)?,
                cost_estimated: r.get::<_, i64>(26)? != 0,
                stream: r.get::<_, i64>(27)? != 0,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn distinct(&self, column: &str) -> Vec<String> {
        let col = match column {
            "provider" => "provider_name",
            "model" => "model_alias",
            "client" => "client_name",
            _ => return vec![],
        };
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(&format!("SELECT DISTINCT {col} FROM requests WHERE {col} <> '' ORDER BY {col}")).unwrap();
        st.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect()
    }

    pub fn export_csv(&self, f: &Filter, path: &Path) -> Result<usize> {
        let rows = self.requests(f, 1_000_000);
        let mut out = String::from(
            "id,timestamp,client,agent,project,endpoint,model_alias,provider,upstream_model,decision,decision_reason,consent,status,latency_ms,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,reasoning_tokens,usage_source,cost,currency,cost_estimated,price_id,error\n",
        );
        let esc = |s: &str| {
            let s = s.trim_start_matches(['=', '+', '-', '@']); // CSV formula injection guard
            if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
        };
        for r in &rows {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{},{}\n",
                r.id,
                r.ts,
                esc(&r.client_name),
                esc(&r.agent),
                esc(&r.project),
                r.endpoint,
                esc(&r.model_alias),
                esc(&r.provider_name),
                esc(&r.upstream_model),
                r.decision,
                esc(&r.decision_reason),
                r.consent,
                r.status,
                r.latency_ms,
                r.usage.input,
                r.usage.output,
                r.usage.cache_read,
                r.usage.cache_write,
                r.usage.reasoning,
                r.usage.source.as_str(),
                r.cost,
                r.currency,
                r.cost_estimated,
                r.price_id,
                esc(&r.error)
            ));
        }
        std::fs::write(path, out)?;
        Ok(rows.len())
    }

    pub fn export_json(&self, f: &Filter, path: &Path) -> Result<usize> {
        let rows = self.requests(f, 1_000_000);
        std::fs::write(path, serde_json::to_string_pretty(&rows)?)?;
        Ok(rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, provider: &str, cost: f64, status: u16, decision: &str) -> RequestRecord {
        RequestRecord {
            id: id.into(),
            ts: crate::config::now_rfc3339(),
            client_id: "c1".into(),
            client_name: "Code Reviewer".into(),
            agent: "vscode".into(),
            model_alias: "m".into(),
            provider_name: provider.into(),
            decision: decision.into(),
            status,
            usage: Usage { input: 100, output: 50, ..Default::default() },
            cost,
            currency: "USD".into(),
            ..Default::default()
        }
    }

    #[test]
    fn summary_aggregates() {
        let a = Audit::in_memory().unwrap();
        a.record(&rec("1", "Azure Foundry", 1.0, 200, "allowed")).unwrap();
        a.record(&rec("2", "Azure Foundry", 2.0, 200, "allowed")).unwrap();
        a.record(&rec("3", "Ollama", 0.0, 500, "allowed")).unwrap();
        a.record(&rec("4", "Ollama", 0.0, 403, "denied")).unwrap();
        let s = a.summary(&Filter { days: 30, ..Default::default() }, &|_| 1.0);
        assert_eq!((s.calls, s.ok, s.errors, s.denied), (4, 2, 1, 1));
        assert!((s.cost - 3.0).abs() < 1e-9);
        assert_eq!(s.by_provider[0].label, "Azure Foundry");
        assert_eq!(s.daily.len(), 30);
        assert_eq!(a.client_spend("c1", "2000-01-01").get("USD").copied().unwrap_or(0.0), 3.0);
    }

    #[test]
    fn csv_export_guards_formula_injection() {
        let a = Audit::in_memory().unwrap();
        let mut r = rec("1", "P", 0.1, 200, "allowed");
        r.agent = "=HYPERLINK(\"http://x\")".into();
        a.record(&r).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.csv");
        a.export_csv(&Filter::default(), &p).unwrap();
        let s = std::fs::read_to_string(p).unwrap();
        assert!(!s.contains(",=HYPERLINK"));
    }
}
