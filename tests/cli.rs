use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_s3-policy-audit")).args(args).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
}

#[test]
fn default_exit_zero_and_header() {
    let (c, out) = run(&["examples"]);
    assert_eq!(c, 0);
    assert!(out.starts_with("4 files, 12 findings\n"));
}

#[test]
fn tsv_format() {
    let (_, out) = run(&["examples", "--tsv"]);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "# 4 files, 12 findings");
    for l in lines {
        assert_eq!(l.split('\t').count(), 4, "{}", l);
    }
}

#[test]
fn fail_on_levels() {
    assert_eq!(run(&["examples", "--fail-on", "critical"]).0, 1);
    assert_eq!(run(&["examples", "--fail-on", "high"]).0, 1);
    assert_eq!(run(&["examples/config/acme-private-data.json", "--fail-on", "medium"]).0, 0);
}

#[test]
fn bad_input_exits_two() {
    for a in [vec!["nope"], vec!["--bogus"], vec![], vec!["examples", "--fail-on", "low"], vec!["examples", "--fail-on"], vec!["examples", "x"]] {
        assert_eq!(run(&a).0, 2, "{:?}", a);
    }
}

#[test]
fn single_file_label() {
    let (_, out) = run(&["examples/policies/public-assets.json", "--tsv"]);
    assert!(out.contains("\tS3001\tpublic-assets.json#Statement[PublicRead]\t"));
}

#[test]
fn binary_input_survives() {
    let dir = std::env::temp_dir().join(format!("s3pa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("b.json");
    std::fs::write(&p, (0..3000u32).map(|i| (i * 31 % 256) as u8).collect::<Vec<u8>>()).unwrap();
    let (c, _) = run(&[p.to_str().unwrap()]);
    assert!(c <= 1);
    std::fs::remove_dir_all(&dir).ok();
}
