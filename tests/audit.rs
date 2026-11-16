use s3audit::{audit, rank, sort, Finding};

fn rules(text: &str) -> Vec<&'static str> {
    let mut r: Vec<&'static str> = audit(text, "t.json").iter().map(|f| f.rule).collect();
    r.sort();
    r
}

fn stmt(s: &str) -> String {
    format!(r#"{{"Version":"2012-10-17","Statement":[{}, {}]}}"#, s, TLS)
}

const TLS: &str = r#"{"Sid":"Tls","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}"#;

#[test]
fn clean_policy() {
    let t = stmt(r#"{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}"#);
    assert!(rules(&t).is_empty());
}

#[test]
fn public_read_is_high() {
    let t = stmt(r#"{"Sid":"R","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}"#);
    let f = audit(&t, "t.json");
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].sev, f[0].rule), ("high", "S3001"));
    assert_eq!(f[0].where_, "t.json#Statement[R]");
}

#[test]
fn public_write_is_critical() {
    for a in ["s3:PutObject", "s3:DeleteObject", "s3:*", "*", "s3:PutObjectAcl", "s3:AbortMultipartUpload", "S3:putobject"] {
        let t = stmt(&format!(r#"{{"Effect":"Allow","Principal":"*","Action":"{}","Resource":"arn:aws:s3:::b/*"}}"#, a));
        let f = audit(&t, "t.json");
        assert_eq!(f[0].sev, "critical", "{}", a);
    }
}

#[test]
fn public_principal_shapes() {
    for p in [r#""*""#, r#"{"AWS":"*"}"#, r#"{"AWS":["arn:aws:iam::1:root","*"]}"#, r#"{"Service":"*"}"#] {
        let t = stmt(&format!(r#"{{"Effect":"Allow","Principal":{},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}"#, p));
        assert_eq!(rules(&t), vec!["S3001"], "{}", p);
    }
}

#[test]
fn public_with_condition_is_medium() {
    let t = stmt(r#"{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:SourceVpce":"v"}}}"#);
    let f = audit(&t, "t.json");
    assert_eq!(f[0].sev, "medium");
}

#[test]
fn empty_condition_does_not_count() {
    let t = stmt(r#"{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"r","Condition":{}}"#);
    assert_eq!(audit(&t, "t.json")[0].sev, "high");
}

#[test]
fn wildcard_action_named_principal() {
    for a in [r#""s3:*""#, r#""*""#, r#"["s3:GetObject","s3:*"]"#] {
        let t = stmt(&format!(r#"{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::1:root"}},"Action":{},"Resource":"arn:aws:s3:::b/*"}}"#, a));
        assert_eq!(rules(&t), vec!["S3002"], "{}", a);
    }
}

#[test]
fn resource_star() {
    let t = stmt(r#"{"Effect":"Allow","Principal":{"AWS":"a"},"Action":"s3:GetObject","Resource":"*"}"#);
    assert_eq!(rules(&t), vec!["S3003"]);
    let t = stmt(r#"{"Effect":"Allow","Principal":{"AWS":"a"},"Action":"s3:GetObject","Resource":["arn:aws:s3:::b/*","*"]}"#);
    assert_eq!(rules(&t), vec!["S3003"]);
}

#[test]
fn not_principal_not_action() {
    let t = stmt(r#"{"Effect":"Allow","NotPrincipal":{"AWS":"a"},"Action":"s3:GetObject","Resource":"r"}"#);
    assert_eq!(rules(&t), vec!["S3010"]);
    let t = stmt(r#"{"Effect":"Allow","Principal":{"AWS":"a"},"NotAction":"s3:Delete*","Resource":"r"}"#);
    assert_eq!(rules(&t), vec!["S3010"]);
}

#[test]
fn deny_statements_are_ignored_for_allow_rules() {
    let t = stmt(r#"{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}"#);
    assert!(rules(&t).is_empty());
}

#[test]
fn tls_enforcement() {
    let no_tls = r#"{"Statement":[{"Effect":"Allow","Principal":{"AWS":"a"},"Action":"s3:GetObject","Resource":"r"}]}"#;
    assert_eq!(rules(no_tls), vec!["S3004"]);
    let if_exists = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"r","Condition":{"BoolIfExists":{"aws:SecureTransport":["false"]}}}]}"#;
    assert!(rules(if_exists).is_empty());
    let wrong = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"r","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}"#;
    assert_eq!(rules(wrong), vec!["S3004"]);
    let empty = r#"{"Statement":[]}"#;
    assert!(rules(empty).is_empty());
}

#[test]
fn single_statement_object() {
    let t = r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"r"}}"#;
    assert_eq!(rules(t), vec!["S3001", "S3004"]);
}

#[test]
fn statement_without_sid_uses_index() {
    let t = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"r"}]}"#;
    assert!(audit(t, "t.json").iter().any(|f| f.where_ == "t.json#Statement[#0]"));
}

fn cfg(body: &str) -> String {
    format!(r#"{{"Bucket":"b",{}}}"#, body)
}

const PAB_OK: &str = r#""PublicAccessBlock":{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}"#;
const OTHER_OK: &str = r#""Encryption":{"Rules":[1]},"Versioning":"Enabled","Logging":{"TargetBucket":"l"}"#;

#[test]
fn clean_config() {
    assert!(rules(&cfg(&format!("{},{}", PAB_OK, OTHER_OK))).is_empty());
}

#[test]
fn public_access_block_variants() {
    assert_eq!(rules(&cfg(OTHER_OK)), vec!["S3005"]);
    let partial = r#""PublicAccessBlock":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":false}"#;
    let t = cfg(&format!("{},{}", partial, OTHER_OK));
    let f = audit(&t, "t.json");
    assert_eq!(f.len(), 1);
    assert!(f[0].msg.contains("RestrictPublicBuckets"));
    let flat_ok = r#""PublicAccessBlock":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}"#;
    assert!(rules(&cfg(&format!("{},{}", flat_ok, OTHER_OK))).is_empty());
    assert_eq!(rules(&cfg(&format!(r#""PublicAccessBlock":null,{}"#, OTHER_OK))), vec!["S3005"]);
}

#[test]
fn encryption_versioning_logging() {
    assert_eq!(rules(&cfg(&format!(r#"{},"Versioning":"Enabled","Logging":{{"a":1}}"#, PAB_OK))), vec!["S3006"]);
    assert_eq!(rules(&cfg(&format!(r#"{},"Encryption":{{}},"Versioning":"Enabled","Logging":{{"a":1}}"#, PAB_OK))), vec!["S3006"]);
    assert_eq!(rules(&cfg(&format!(r#"{},"Encryption":{{"a":1}},"Versioning":"Suspended","Logging":{{"a":1}}"#, PAB_OK))), vec!["S3007"]);
    assert!(rules(&cfg(&format!(r#"{},"Encryption":{{"a":1}},"Versioning":{{"Status":"Enabled"}},"Logging":{{"a":1}}"#, PAB_OK))).is_empty());
    assert_eq!(rules(&cfg(&format!(r#"{},"Encryption":{{"a":1}},"Versioning":"Enabled","Logging":null"#, PAB_OK))), vec!["S3008"]);
    assert_eq!(rules(&cfg(&format!(r#"{},"Encryption":{{"a":1}},"Versioning":"Enabled","Logging":false"#, PAB_OK))), vec!["S3008"]);
}

#[test]
fn acl_grants() {
    let g = |uri: &str, perm: &str| {
        cfg(&format!(r#"{},{},"Acl":{{"Grants":[{{"Grantee":{{"URI":"http://acs.amazonaws.com/groups/global/{}"}},"Permission":"{}"}}]}}"#, PAB_OK, OTHER_OK, uri, perm))
    };
    let f = audit(&g("AllUsers", "READ"), "t.json");
    assert_eq!((f[0].sev, f[0].rule), ("high", "S3009"));
    assert_eq!(audit(&g("AllUsers", "WRITE"), "t.json")[0].sev, "critical");
    assert_eq!(audit(&g("AllUsers", "FULL_CONTROL"), "t.json")[0].sev, "critical");
    assert_eq!(audit(&g("AuthenticatedUsers", "WRITE"), "t.json")[0].sev, "high");
    assert!(rules(&g("LogDelivery", "WRITE")).is_empty());
}

#[test]
fn policy_and_config_in_one_file() {
    let t = r#"{"Bucket":"b","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"r"}]}"#;
    let r = rules(t);
    assert!(r.contains(&"S3001") && r.contains(&"S3005"));
}

#[test]
fn not_s3_json() {
    assert_eq!(rules(r#"{"a":1}"#), vec!["S3000"]);
    assert_eq!(rules("[]"), vec!["S3000"]);
    assert_eq!(rules("42"), vec!["S3000"]);
    assert_eq!(rules("null"), vec!["S3000"]);
    assert_eq!(rules("{nope"), vec!["S3000"]);
    assert_eq!(rules(""), vec!["S3000"]);
    assert_eq!(audit("", "e")[0].sev, "info");
}

#[test]
fn wrong_types_survive() {
    for t in [
        r#"{"Statement":"x"}"#,
        r#"{"Statement":[1,null,"a",[]]}"#,
        r#"{"Statement":[{"Effect":5,"Principal":[],"Action":{"a":1},"Resource":null}]}"#,
        r#"{"Bucket":1,"PublicAccessBlock":5,"Acl":{"Grants":"x"},"Versioning":[],"Logging":[],"Encryption":5}"#,
        r#"{"Bucket":"b","Acl":{"Grants":[1,{"Grantee":5}]}}"#,
    ] {
        let _ = audit(t, "t.json");
    }
}

#[test]
fn deep_json_does_not_crash() {
    let t = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    assert_eq!(rules(&t), vec!["S3000"]);
}

#[test]
fn sorting() {
    let mk = |sev: &'static str, rule: &'static str, file: &str| Finding { sev, rule, file: file.into(), where_: file.into(), msg: String::new() };
    let s = sort(vec![mk("low", "B", "a"), mk("high", "A", "z"), mk("high", "A", "a"), mk("critical", "Z", "z")]);
    let order: Vec<String> = s.iter().map(|f| format!("{}{}", f.sev, f.file)).collect();
    assert_eq!(order, vec!["criticalz", "higha", "highz", "lowa"]);
    assert!(rank("critical") < rank("high") && rank("low") < rank("info"));
}

#[test]
fn fuzz_random_and_truncated() {
    let mut seed: u64 = 7;
    let mut next = |n: usize| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as usize) % n
    };
    let bits = ["{", "}", "[", "]", ",", ":", "\"Statement\"", "\"Effect\"", "\"Allow\"", "\"Principal\"", "\"*\"", "\"Action\"", "\"Bucket\"", "1", "null", "true", "\"x\""];
    for _ in 0..3000 {
        let mut s = String::new();
        for _ in 0..(1 + next(40)) {
            s.push_str(bits[next(bits.len())]);
        }
        let _ = audit(&s, "f.json");
    }
    let valid = std::fs::read_to_string("examples/policies/public-assets.json").unwrap();
    for i in 0..=valid.len() {
        if valid.is_char_boundary(i) {
            let _ = audit(&valid[..i], "f.json");
        }
    }
}
