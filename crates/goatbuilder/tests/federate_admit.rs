//! Confirmation 2, phase 10 by the command, through the real binary against
//! the stand-in repository (federate_world): the summary and its digest, the
//! approval bound to it, the core's access control assembled, the dry run
//! and the restart, inside `deploy`.

mod federate_world;

use std::path::Path;

use federate_world::{phases_run, public_b64, rows, says, sha256_hex, world, World};

fn sha256_file(p: &Path) -> String {
    sha256_hex(&std::fs::read(p).unwrap())
}

/// Phases 1 to 9 with confirmation 1 by flag, and a plan; returns its hash.
fn ready(w: &World, confirm_digest: bool) -> String {
    let fp = sha256_hex(b"fake-ca-der");
    let key = public_b64("xab");
    // compose writes a fixed agreement in the stand-in, so its digest is known.
    let digest = sha256_file(&w.root.path().join("fake/agreement.json"));
    let mut args = vec![
        "hello-ally",
        "--to",
        "9",
        "--partner-key",
        &key,
        "--partner-ca-fingerprint",
        &fp,
    ];
    if confirm_digest {
        args.extend(["--agreement-digest", &digest]);
    }
    let (out, v) = w.run(&args);
    assert!(out.status.success(), "{}", says(&out));
    if confirm_digest {
        assert_eq!(
            phases_run(&v),
            [1, 2, 3, 4, 5, 6, 7, 8, 9],
            "{}",
            says(&out)
        );
    }
    let frag = w.work.join("applied/ops/federation/acl/xab-fragment.json5");
    let plan = format!(
        r#"{{"peering":"hello-ally","agreement_digest":"{digest}","artifacts":[{{"path":"applied/ops/federation/acl/xab-fragment.json5","sha256":"{}"}}]}}"#,
        sha256_file(&frag)
    );
    std::fs::write(w.work.join("plan.json"), plan).unwrap();
    sha256_file(&w.work.join("plan.json"))
}

/// The digest to approve, from the stop's row.
fn admission_digest(v: &serde_json::Value) -> String {
    let d = rows(v, "stopped")
        .into_iter()
        .find(|d| d.contains("--approve-admission"))
        .expect("the stop names the digest")
        .to_string();
    d.split("--approve-admission ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn deploy_admits_the_edge_after_the_admission_is_approved_by_its_digest() {
    let w = world();
    let plan = ready(&w, true);
    w.clear_log();
    // Asked to admit, with nothing approved yet: the summary and its digest, and a stop.
    let (out, v) = w.run(&[
        "deploy",
        "hello-ally",
        "--approve-plan",
        &plan,
        "--review-in-pr",
    ]);
    assert!(out.status.success(), "{}", says(&out));
    assert!(
        rows(&v, "stopped").iter().any(|d| d.starts_with("GB-197")),
        "{}",
        says(&out)
    );
    let review = std::fs::read_to_string(w.work.join("admission/review.md")).unwrap();
    assert!(
        review.contains("fed.xab.xaa.01") && review.contains(&plan),
        "the summary names the plan: {review}"
    );
    let digest = review
        .split("--approve-admission ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert!(
        !w.root.path().join("core/config.json5").exists(),
        "nothing on the core changed"
    );

    // Approved by its digest: merged, assembled, dry run, restart, then 11 to 13.
    w.clear_log();
    let (out, v) = w.run(&[
        "deploy",
        "hello-ally",
        "--approve-plan",
        &plan,
        "--approve-admission",
        &digest,
    ]);
    assert!(out.status.success(), "{}", says(&out));
    assert_eq!(phases_run(&v), [1, 10, 11, 12, 13], "{}", says(&out));
    let cfg = std::fs::read_to_string(w.root.path().join("core/config.json5")).unwrap();
    assert!(
        cfg.contains("fed-w-xab") && cfg.contains("fed.xab.xaa.01"),
        "{cfg}"
    );
    let log = w.log();
    let (dry, restart, play) = (
        log.find("dry-run").unwrap(),
        log.find("restart").unwrap(),
        log.find("peering-wg.yml").unwrap(),
    );
    assert!(
        dry < restart && restart < play,
        "dry run, then restart, then the transport: {log}"
    );
    assert!(w.work.join("pki/partner-ca.pem").is_file());
    let st = w.state();
    assert!(st["confirmations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["kind"] == "admission"
            && c["bound_to"] == digest.as_str()
            && c["values"]["plan"] == plan.as_str()));
    assert_eq!(st["phases"]["10"]["outcome"], "passed");
}

#[test]
fn another_digest_or_an_unconfirmed_agreement_changes_nothing() {
    let w = world();
    // Keys confirmed at phase 5; phases 6 to 9 run without comparing the digest.
    let (fp, key) = (sha256_hex(b"fake-ca-der"), public_b64("xab"));
    let (out, _) = w.run(&[
        "hello-ally",
        "--to",
        "5",
        "--partner-key",
        &key,
        "--partner-ca-fingerprint",
        &fp,
    ]);
    assert!(out.status.success(), "{}", says(&out));
    let (out, _) = w.run(&["hello-ally", "--from", "6", "--to", "9"]);
    assert!(out.status.success(), "{}", says(&out));
    let frag = w.work.join("applied/ops/federation/acl/xab-fragment.json5");
    let body = format!(
        r#"{{"peering":"hello-ally","agreement_digest":"{}","artifacts":[{{"path":"applied/ops/federation/acl/xab-fragment.json5","sha256":"{}"}}]}}"#,
        sha256_file(&w.work.join("agreement.json")),
        sha256_file(&frag)
    );
    std::fs::write(w.work.join("plan.json"), body).unwrap();
    let plan = sha256_file(&w.work.join("plan.json"));

    // Another digest.
    let (out, _) = w.run(&[
        "deploy",
        "hello-ally",
        "--approve-plan",
        &plan,
        "--approve-admission",
        "sha256:00",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", says(&out));
    assert!(says(&out).contains("GB-194"), "{}", says(&out));

    // The right digest, but the agreement was never compared with the partner.
    let (_, v) = w.run(&["deploy", "hello-ally", "--approve-plan", &plan, "--confirm"]);
    let digest = admission_digest(&v);
    w.clear_log();
    let (out, _) = w.run(&[
        "deploy",
        "hello-ally",
        "--approve-plan",
        &plan,
        "--approve-admission",
        &digest,
    ]);
    let text = says(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains("GB-194") && text.contains("has not been confirmed with the partner"),
        "{text}"
    );
    assert!(
        !w.root.path().join("core/config.json5").exists(),
        "nothing on the core changed"
    );
    assert!(!w.log().contains("restart"), "{}", w.log());
}

#[test]
fn without_the_flags_phase_10_stops_as_before() {
    let w = world();
    let plan = ready(&w, true);
    let (out, v) = w.run(&["deploy", "hello-ally", "--approve-plan", &plan]);
    assert!(out.status.success(), "{}", says(&out));
    assert_eq!(phases_run(&v), [1, 10]);
    assert!(
        rows(&v, "note").iter().any(|d| d.contains("OPERATOR STEP")),
        "{}",
        says(&out)
    );
    assert!(!w.root.path().join("core/config.json5").exists());
}

#[test]
fn a_failed_dry_run_puts_every_file_back() {
    let w = world();
    let plan = ready(&w, true);
    let org_before = std::fs::read_to_string(w.root.path().join("core/org.json5")).unwrap();
    let (_, v) = w.run(&["deploy", "hello-ally", "--approve-plan", &plan, "--confirm"]);
    let digest = admission_digest(&v);
    let out = w
        .command(&[
            "deploy",
            "hello-ally",
            "--approve-plan",
            &plan,
            "--approve-admission",
            &digest,
        ])
        .env("FED_CORE_DRY_RUN", "exit 3")
        .output()
        .unwrap();
    let text = says(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains("GB-195") && text.contains("every file placed is put back"),
        "{text}"
    );
    assert_eq!(
        org_before,
        std::fs::read_to_string(w.root.path().join("core/org.json5")).unwrap()
    );
    assert!(
        !w.root.path().join("core/config.json5").exists(),
        "a file that was not there is gone again"
    );
    assert!(!w.work.join("pki/partner-ca.pem").exists());
}

#[test]
fn a_failed_restart_keeps_the_first_backup_when_retried() {
    let w = world();
    let plan = ready(&w, true);
    let org_before = std::fs::read_to_string(w.root.path().join("core/org.json5")).unwrap();
    // The restart route is part of what is approved, so the digest is read
    // with the same settings it is approved under.
    let out = w
        .command(&["deploy", "hello-ally", "--approve-plan", &plan, "--confirm"])
        .env("FED_CORE_RESTART", "exit 4")
        .output()
        .unwrap();
    let digest = admission_digest(&serde_json::from_slice(&out.stdout).unwrap());
    let out = w
        .command(&[
            "deploy",
            "hello-ally",
            "--approve-plan",
            &plan,
            "--approve-admission",
            &digest,
        ])
        .env("FED_CORE_RESTART", "exit 4")
        .output()
        .unwrap();
    assert!(says(&out).contains("GB-196"), "{}", says(&out));
    // The original is in that run's backup folder.
    let backups: Vec<_> = walk(&w.work.join("admission"))
        .into_iter()
        .filter(|p| {
            p.to_string_lossy().contains("/backup/") && p.to_string_lossy().ends_with("org.json5")
        })
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(org_before, std::fs::read_to_string(&backups[0]).unwrap());
    // Retried: a new digest (the org fragment in place changed), a new backup folder.
    let (_, v) = w.run(&["deploy", "hello-ally", "--approve-plan", &plan, "--confirm"]);
    let digest2 = admission_digest(&v);
    let (out, _) = w.run(&[
        "deploy",
        "hello-ally",
        "--approve-plan",
        &plan,
        "--approve-admission",
        &digest2,
    ]);
    assert!(out.status.success(), "{}", says(&out));
    assert_eq!(
        org_before,
        std::fs::read_to_string(&backups[0]).unwrap(),
        "the first backup is never overwritten"
    );
}

fn walk(d: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}
