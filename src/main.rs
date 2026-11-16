use s3audit::{audit, rank, sort, Finding};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

fn usage() -> ! {
    eprintln!("usage: s3-policy-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.");
    exit(2)
}

fn walk(dir: &Path, root: &Path, depth: usize, out: &mut Vec<(String, PathBuf)>) {
    if depth > 30 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut ents: Vec<_> = rd.filter_map(Result::ok).collect();
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let p = e.path();
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            if e.file_name() != ".git" {
                walk(&p, root, depth + 1, out);
            }
        } else if p.extension().map(|x| x == "json").unwrap_or(false) {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            out.push((rel, p));
        }
    }
}

fn main() {
    let mut path: Option<String> = None;
    let mut tsv = false;
    let mut fail_on: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tsv" => tsv = true,
            "--fail-on" => match args.next() {
                Some(v) if v == "medium" || v == "high" || v == "critical" => fail_on = Some(v),
                _ => usage(),
            },
            x if x.starts_with('-') => usage(),
            x => {
                if path.is_some() {
                    usage();
                }
                path = Some(x.to_string());
            }
        }
    }
    let path = path.unwrap_or_else(|| usage());
    let p = Path::new(&path);
    if !p.exists() {
        eprintln!("error: no such file or directory: {}", path);
        exit(2);
    }
    let mut files: Vec<(String, PathBuf)> = vec![];
    if p.is_dir() {
        walk(p, p, 0, &mut files);
    } else {
        files.push((p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or(path.clone()), p.to_path_buf()));
    }
    let mut all: Vec<Finding> = vec![];
    for (label, fp) in &files {
        if fs::metadata(fp).map(|m| m.len() > 20_000_000).unwrap_or(true) {
            continue;
        }
        let Ok(bytes) = fs::read(fp) else { continue };
        all.extend(audit(&String::from_utf8_lossy(&bytes), label));
    }
    let all = sort(all);
    let head = format!("{} files, {} findings", files.len(), all.len());
    println!("{}", if tsv { format!("# {}", head) } else { head });
    for x in &all {
        if tsv {
            println!("{}\t{}\t{}\t{}", x.sev, x.rule, x.where_, x.msg);
        } else {
            println!("{:<8} {} {}\n         {}", x.sev.to_uppercase(), x.rule, x.where_, x.msg);
        }
    }
    if let Some(l) = fail_on {
        if all.iter().any(|x| rank(x.sev) <= rank(&l)) {
            exit(1);
        }
    }
}
