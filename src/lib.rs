//! S3 policy and bucket configuration audit.
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub sev: &'static str,
    pub rule: &'static str,
    pub file: String,
    pub where_: String,
    pub msg: String,
}

pub fn rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn f(sev: &'static str, rule: &'static str, file: &str, loc: &str, msg: String) -> Finding {
    let where_ = if loc.is_empty() { file.to_string() } else { format!("{}#{}", file, loc) };
    Finding { sev, rule, file: file.to_string(), where_, msg }
}

fn as_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

fn is_public_principal(p: Option<&Value>) -> bool {
    match p {
        Some(Value::String(s)) => s == "*",
        Some(Value::Object(o)) => o.values().any(|v| as_list(Some(v)).iter().any(|s| s == "*")),
        _ => false,
    }
}

fn is_write(action: &str) -> bool {
    let a = action.to_ascii_lowercase();
    a == "*"
        || a == "s3:*"
        || ["s3:put", "s3:delete", "s3:replicate", "s3:restore", "s3:abort", "s3:create"].iter().any(|p| a.starts_with(p))
}

fn is_wild(action: &str) -> bool {
    action == "*" || action.eq_ignore_ascii_case("s3:*")
}

fn deny_tls(stmt: &Value) -> bool {
    if stmt.get("Effect").and_then(Value::as_str) != Some("Deny") {
        return false;
    }
    let Some(cond) = stmt.get("Condition").and_then(Value::as_object) else { return false };
    for (op, body) in cond {
        let opl = op.to_ascii_lowercase();
        if opl == "bool" || opl == "boolifexists" {
            if let Some(b) = body.as_object() {
                for (k, v) in b {
                    if k.eq_ignore_ascii_case("aws:SecureTransport") && as_list(Some(v)).iter().any(|s| s.eq_ignore_ascii_case("false")) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn audit_policy(doc: &Value, file: &str, out: &mut Vec<Finding>) {
    let stmts: Vec<&Value> = match doc.get("Statement") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v @ Value::Object(_)) => vec![v],
        _ => vec![],
    };
    let mut tls = false;
    for (i, s) in stmts.iter().enumerate() {
        if !s.is_object() {
            continue;
        }
        if deny_tls(s) {
            tls = true;
        }
        if s.get("Effect").and_then(Value::as_str) != Some("Allow") {
            continue;
        }
        let sid = s.get("Sid").and_then(Value::as_str).map(String::from).unwrap_or_else(|| format!("#{}", i));
        let loc = format!("Statement[{}]", sid);
        let actions = as_list(s.get("Action"));
        let has_cond = s.get("Condition").map(|c| c.as_object().map(|o| !o.is_empty()).unwrap_or(false)).unwrap_or(false);
        let public = is_public_principal(s.get("Principal"));
        if public {
            if has_cond {
                out.push(f("medium", "S3001", file, &loc, "public principal with a Condition: check that the condition really restricts who can call".to_string()));
            } else if actions.iter().any(|a| is_write(a)) {
                out.push(f("critical", "S3001", file, &loc, format!("anyone can write or delete: Action {}", actions.join(", "))));
            } else {
                out.push(f("high", "S3001", file, &loc, format!("anyone on the internet can read: Action {}", actions.join(", "))));
            }
        } else if actions.iter().any(|a| is_wild(a)) {
            out.push(f("medium", "S3002", file, &loc, "wildcard action for a named principal: grant only the actions needed".to_string()));
        }
        if as_list(s.get("Resource")).iter().any(|r| r == "*") {
            out.push(f("medium", "S3003", file, &loc, "Resource is *: scope it to the bucket and its objects".to_string()));
        }
        if s.get("NotPrincipal").is_some() || s.get("NotAction").is_some() {
            out.push(f("medium", "S3010", file, &loc, "Allow with NotPrincipal or NotAction grants everything except the listed items".to_string()));
        }
    }
    if !stmts.is_empty() && !tls {
        out.push(f("medium", "S3004", file, "", "no statement denies requests where aws:SecureTransport is false".to_string()));
    }
}

fn audit_config(doc: &Value, file: &str, out: &mut Vec<Finding>) {
    let pab = doc.get("PublicAccessBlock").map(|v| v.get("PublicAccessBlockConfiguration").unwrap_or(v));
    match pab {
        Some(Value::Object(o)) => {
            let missing: Vec<&str> = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
                .into_iter()
                .filter(|k| o.get(*k).and_then(Value::as_bool) != Some(true))
                .collect();
            if !missing.is_empty() {
                out.push(f("high", "S3005", file, "PublicAccessBlock", format!("public access block is not fully on: {} not true", missing.join(", "))));
            }
        }
        _ => out.push(f("high", "S3005", file, "PublicAccessBlock", "no public access block configured".to_string())),
    }
    let enc = doc.get("Encryption");
    if enc.map(|e| e.is_null() || e.as_object().map(|o| o.is_empty()).unwrap_or(false) || e == &Value::Bool(false)).unwrap_or(true) {
        out.push(f("medium", "S3006", file, "Encryption", "no default encryption configured".to_string()));
    }
    let ver = doc.get("Versioning").and_then(|v| v.as_str().map(String::from).or_else(|| v.get("Status").and_then(Value::as_str).map(String::from)));
    if ver.as_deref() != Some("Enabled") {
        out.push(f("low", "S3007", file, "Versioning", "versioning is not enabled: deletes and overwrites cannot be undone".to_string()));
    }
    let log = doc.get("Logging");
    if log.map(|l| l.is_null() || l == &Value::Bool(false) || l.as_object().map(|o| o.is_empty()).unwrap_or(false)).unwrap_or(true) {
        out.push(f("low", "S3008", file, "Logging", "server access logging is off".to_string()));
    }
    let grants = doc.get("Acl").and_then(|a| a.get("Grants")).and_then(Value::as_array).cloned().unwrap_or_default();
    for (i, g) in grants.iter().enumerate() {
        let uri = g.get("Grantee").and_then(|x| x.get("URI")).and_then(Value::as_str).unwrap_or("");
        let perm = g.get("Permission").and_then(Value::as_str).unwrap_or("");
        let all_users = uri.ends_with("/AllUsers");
        if all_users || uri.ends_with("/AuthenticatedUsers") {
            let who = if all_users { "everyone" } else { "any AWS account" };
            let sev = if all_users && (perm == "WRITE" || perm == "FULL_CONTROL" || perm == "WRITE_ACP") { "critical" } else { "high" };
            out.push(f(sev, "S3009", file, &format!("Acl.Grants[{}]", i), format!("ACL grants {} to {}", perm, who)));
        }
    }
}

pub fn audit(text: &str, file: &str) -> Vec<Finding> {
    let doc: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return vec![f("info", "S3000", file, "", "not valid JSON, ignored".to_string())],
    };
    let mut out = vec![];
    if !doc.is_object() {
        return vec![f("info", "S3000", file, "", "not a JSON object, ignored".to_string())];
    }
    let is_policy = doc.get("Statement").is_some();
    let is_config = doc.get("Bucket").is_some() || doc.get("PublicAccessBlock").is_some() || doc.get("Acl").is_some();
    if is_policy {
        audit_policy(&doc, file, &mut out);
    }
    if is_config {
        audit_config(&doc, file, &mut out);
    }
    if !is_policy && !is_config {
        out.push(f("info", "S3000", file, "", "neither a bucket policy nor a bucket configuration export, ignored".to_string()));
    }
    out
}

pub fn sort(mut v: Vec<Finding>) -> Vec<Finding> {
    v.sort_by(|a, b| (rank(a.sev), &a.file, a.rule, &a.where_).cmp(&(rank(b.sev), &b.file, b.rule, &b.where_)));
    v
}
