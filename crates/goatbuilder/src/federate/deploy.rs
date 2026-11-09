//! `goatbuilder federate deploy <partner>` and `goatbuilder federate test
//! <partner>`: two stages of a peering, each run alone.
//!
//! `deploy` executes an approved plan through the existing plays. `apply`
//! stays a renderer; this is the separate, named step that changes hosts.
//!
//! 1. The plan is read (`<work>/plan.json`, or `--plan`) and its hash taken
//!    over its exact bytes. A hash written inside the plan is never trusted.
//!    A plan that does not say what it was made from is refused (GB-187).
//! 2. Approval binds to that hash: `--approve-plan <hash>`, or a person at a
//!    terminal types `yes` after reading the plan and its hash. `--yes` never
//!    approves a plan. Without either, nothing runs (GB-186).
//! 3. One run, under the peering's lock, then: reads the plan again and
//!    refuses if its bytes changed since they were approved (GB-187); compares
//!    the agreement and the whole rendered set (every file under
//!    `<work>/applied/`, plus any minted file the plan lists) with what the
//!    plan names, and refuses on any difference, because changed inputs need
//!    a new plan (GB-188); when the run starts after phase 10, refuses unless
//!    phase 10 is recorded as done for what is rendered now (GB-190); claims
//!    the resources the plan names on shared hosts (the host-level allocation
//!    check, GB-181); records the approval, bound to the hash; runs phase 1
//!    (the live preflight) immediately before anything changes; then phases
//!    10 to 13 through the existing plays, checking the plan's inputs again
//!    before each of 11, 12 and 13. A refusal is journaled as a `refused` run.
//!
//! Phase 10 is still the by-hand admission on our core: the first deploy
//! stops there, and `deploy <partner> --from 11` (with the same approval)
//! declares it done and carries on. A later deploy skips phase 10 while that
//! declaration holds and its inputs are unchanged; phases 11 to 13 always run
//! (each play is idempotent).
//!
//! `test` runs phase 14, acceptance, and nothing else.
//!
//! The plan document is produced by `goatbuilder federate plan` (stage 6).
//! What this file reads from it: `peering`, `agreement_digest` (`sha256:`
//! over agreement.json) and `artifacts` (`[{path, sha256}]`, paths relative to
//! the working folder, under `applied/` or `pki/`) are required; `resources`
//! (`[{kind, scope, value}]`, `scope` being the host) is read when present.
//! A malformed entry refuses the whole plan. Anything else in it is shown to
//! the person approving and otherwise left alone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::lock::Want;
use super::prompt::{self, groups, Ask};
use super::run::Surface;
use super::{federate_with, Options};
use crate::Report;

/// The phases `deploy` runs after the live preflight: the ones that change
/// hosts. And `test`: acceptance.
pub const DEPLOY_FROM: u32 = 10;
pub const DEPLOY_TO: u32 = 13;
pub const TEST: u32 = 14;

/// A plan as deploy reads it.
#[derive(Debug, Clone)]
pub struct Plan {
    pub path: PathBuf,
    /// `sha256:` over the file's bytes.
    pub hash: String,
    pub peering: String,
    pub agreement: String,
    /// Each rendered or minted file, relative to the working folder, with the
    /// hash the plan saw.
    pub artifacts: BTreeMap<PathBuf, String>,
    pub resources: Vec<Want>,
    pub doc: serde_json::Value,
}

/// An approved plan, as the run checks it again under the lock.
#[derive(Debug, Clone)]
pub struct Approved {
    pub path: PathBuf,
    pub hash: String,
    /// `terminal` or `flag`.
    pub how: String,
    pub agreement: String,
    pub artifacts: BTreeMap<PathBuf, String>,
    pub resources: Vec<Want>,
}

pub fn sha256_bytes(b: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(b))
}

fn coded(code: &str, msg: String) -> anyhow::Error {
    goat_errors::coded(code, msg).into()
}

/// A path the plan may name: relative, plain names only, under `applied/`
/// or `pki/`.
fn plan_path(p: &str) -> Option<PathBuf> {
    let path = Path::new(p);
    let plain = path.components().all(|c| matches!(c, Component::Normal(_)));
    let top = path
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str());
    (plain && matches!(top, Some("applied" | "pki")) && path.components().count() > 1)
        .then(|| path.to_path_buf())
}

fn value_str(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Every file under `dir`, relative to `base`.
fn files_under(base: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => files_under(base, &p, out),
            Ok(_) => {
                if let Ok(rel) = p.strip_prefix(base) {
                    out.insert(rel.to_path_buf());
                }
            }
            Err(_) => {}
        }
    }
}

impl Plan {
    /// Read a plan, take its hash, and check it says what it was made from.
    pub fn read(path: &Path) -> Result<Plan> {
        let bad = |why: String| {
            coded(
                "GB-187",
                format!("deploy: the plan {} {why}", path.display()),
            )
        };
        let bytes = std::fs::read(path).map_err(|e| {
            coded(
                "GB-187",
                format!("deploy: cannot read the plan {} ({e}); a plan is made by `goatbuilder federate plan <partner>` (stage 6)", path.display()),
            )
        })?;
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| bad(format!("does not parse ({e})")))?;
        let peering = doc
            .get("peering")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let agreement = doc
            .get("agreement_digest")
            .and_then(|v| v.as_str())
            .filter(|v| v.starts_with("sha256:"))
            .map(String::from)
            .ok_or_else(|| {
                bad("does not name the agreement it was made from (agreement_digest)".into())
            })?;
        let Some(arts) = doc
            .get("artifacts")
            .and_then(|a| a.as_array())
            .filter(|a| !a.is_empty())
        else {
            return Err(bad(
                "does not list the rendered files it was made from (artifacts)".into(),
            ));
        };
        let mut artifacts = BTreeMap::new();
        for (i, a) in arts.iter().enumerate() {
            let p = a.get("path").and_then(|v| v.as_str()).and_then(plan_path);
            let h = a
                .get("sha256")
                .and_then(|v| v.as_str())
                .filter(|v| v.starts_with("sha256:"));
            match (p, h) {
                (Some(p), Some(h)) => {
                    artifacts.insert(p, h.to_string());
                }
                _ => return Err(bad(format!("has a malformed artifacts[{i}]: each needs a path under applied/ or pki/ (relative, no ..) and a sha256:"))),
            }
        }
        let mut resources = Vec::new();
        match doc.get("resources") {
            None => {}
            Some(serde_json::Value::Array(rs)) => {
                for (i, r) in rs.iter().enumerate() {
                    let k = r
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty());
                    let sc = r
                        .get("scope")
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty());
                    let v = r.get("value").and_then(value_str);
                    match (k, sc, v) {
                        (Some(k), Some(sc), Some(v)) => resources.push(Want::new(k, sc, &v)),
                        _ => return Err(bad(format!("has a malformed resources[{i}]: each needs a kind, a scope (the host) and a value (text or number)"))),
                    }
                }
            }
            Some(_) => return Err(bad("has resources that are not a list".into())),
        }
        Ok(Plan {
            path: path.to_path_buf(),
            hash: sha256_bytes(&bytes),
            peering,
            agreement,
            artifacts,
            resources,
            doc,
        })
    }

    /// What the person approving reads.
    pub fn summary(&self) -> String {
        let mut s = format!("\nThe plan to deploy: {}\n", self.path.display());
        if let Some(schema) = self.doc.get("schema").and_then(|v| v.as_str()) {
            s.push_str(&format!("  schema:     {schema}\n"));
        }
        s.push_str(&format!(
            "  peering:    {}\n  agreement:  {}\n",
            self.peering, self.agreement
        ));
        s.push_str("  made from (each checked against its hash before anything changes):\n");
        for p in self.artifacts.keys() {
            s.push_str(&format!("    {}\n", p.display()));
        }
        if !self.resources.is_empty() {
            s.push_str("  takes:\n");
            for w in &self.resources {
                s.push_str(&format!("    {} {} on {}\n", w.kind, w.value, w.scope));
            }
        }
        if let Some(obj) = self.doc.as_object() {
            let other: Vec<&str> = obj
                .keys()
                .map(String::as_str)
                .filter(|k| {
                    ![
                        "schema",
                        "peering",
                        "agreement_digest",
                        "artifacts",
                        "resources",
                    ]
                    .contains(k)
                })
                .collect();
            if !other.is_empty() {
                s.push_str(&format!(
                    "  also in the plan (read it before approving): {}\n",
                    other.join(", ")
                ));
            }
        }
        s.push_str(&format!(
            "  plan hash:  {}\n              {}\n",
            self.hash,
            groups(&self.hash)
        ));
        s
    }

    fn approved(&self, how: &str) -> Approved {
        Approved {
            path: self.path.clone(),
            hash: self.hash.clone(),
            how: how.into(),
            agreement: self.agreement.clone(),
            artifacts: self.artifacts.clone(),
            resources: self.resources.clone(),
        }
    }
}

/// Bind approval to the plan's hash: a flag that names exactly that hash, or
/// a person at a terminal typing `yes`. Never `--yes`, never silence.
pub fn approve(plan: &Plan, flag: Option<&str>, ask: &mut dyn Ask) -> Result<Approved> {
    let how = match flag {
        Some(v) if prompt::same_value(v, &plan.hash) => "flag",
        Some(v) => {
            return Err(coded(
                "GB-186",
                format!("deploy: --approve-plan {v} is not the hash of the plan in {} ({}); read the plan again and approve the hash it has now", plan.path.display(), plan.hash),
            ))
        }
        None if ask.interactive() => {
            ask.say(&plan.summary());
            let a = ask.ask("Type yes to approve exactly this plan and deploy it; anything else stops:");
            if !prompt::is_yes(&a) {
                return Err(coded("GB-186", "deploy: the plan was not approved; nothing changed".into()));
            }
            "terminal"
        }
        None => {
            return Err(coded(
                "GB-186",
                format!(
                    "deploy: the plan needs approval and there is no terminal to ask at; read {} and pass --approve-plan {} (--yes never approves a plan)",
                    plan.path.display(),
                    plan.hash
                ),
            ))
        }
    };
    Ok(plan.approved(how))
}

/// Just before anything changes, and again before each phase that changes a
/// host: the plan's bytes are the ones approved, and the agreement and the
/// whole rendered set are still what the plan was made from.
pub fn still_holds(a: &Approved, work: &Path) -> Result<()> {
    let now = std::fs::read(&a.path)
        .map(|b| sha256_bytes(&b))
        .unwrap_or_default();
    if now != a.hash {
        return Err(coded(
            "GB-187",
            format!("deploy: the plan {} changed after it was approved (approved {}, now {}); nothing more runs", a.path.display(), a.hash, if now.is_empty() { "unreadable".into() } else { now }),
        ));
    }
    let mut changed = Vec::new();
    let have = std::fs::read(work.join("agreement.json"))
        .map(|b| sha256_bytes(&b))
        .unwrap_or_default();
    if have != a.agreement {
        changed.push(format!(
            "the agreement ({} now, {} in the plan)",
            if have.is_empty() {
                "absent".into()
            } else {
                have
            },
            a.agreement
        ));
    }
    for (p, want) in &a.artifacts {
        let have = std::fs::read(work.join(p))
            .map(|b| sha256_bytes(&b))
            .unwrap_or_default();
        if &have != want {
            changed.push(if have.is_empty() {
                format!("{} (gone)", p.display())
            } else {
                p.display().to_string()
            });
        }
    }
    let mut on_disk = BTreeSet::new();
    files_under(work, &work.join("applied"), &mut on_disk);
    for p in on_disk.iter().filter(|p| !a.artifacts.contains_key(*p)) {
        changed.push(format!("{} (not in the plan)", p.display()));
    }
    if !changed.is_empty() {
        return Err(coded(
            "GB-188",
            format!("deploy: what the plan was made from has changed: {}; make a new plan and approve it", changed.join(", ")),
        ));
    }
    Ok(())
}

/// The command that runs deploy again with the same approval.
fn again(o: &Options, plan: &Plan, plan_flag: Option<&Path>) -> String {
    let mut c = format!("goatbuilder federate deploy {}", o.with);
    for (flag, v) in [
        ("--env", o.env),
        ("--as", o.r#as),
        ("--edge-group", o.edge_group),
        ("--work", o.work),
    ] {
        if let Some(v) = v {
            c.push_str(&format!(" {flag} {v}"));
        }
    }
    if let Some(p) = plan_flag {
        c.push_str(&format!(" --plan {}", p.display()));
    }
    c.push_str(&format!(" --approve-plan {}", plan.hash));
    c
}

/// `goatbuilder federate deploy <partner>`. `o.from` is 1 (the default) or
/// 10 for the whole deploy, or 11 once the admission is done by hand.
pub fn deploy(
    repo: &Path,
    o: &Options,
    plan_flag: Option<&Path>,
    approve_flag: Option<&str>,
    ask: &mut dyn Ask,
) -> Result<Report> {
    let from = match o.from {
        1 | DEPLOY_FROM => DEPLOY_FROM,
        11 => 11,
        n => {
            return Err(coded(
                "GB-189",
                format!("deploy: --from {n} is not a deploy start: deploy runs phase 10 (the admission on our core) then 11 to 13; pass --from 11 once the admission is done by hand"),
            ))
        }
    };
    let work = super::work_dir(o);
    let path = plan_flag
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(&work).join("plan.json"));
    let plan = Plan::read(&path)?;
    if plan.peering != o.with {
        return Err(coded(
            "GB-187",
            format!(
                "deploy: the plan {} is for peering '{}', not '{}'",
                path.display(),
                plan.peering,
                o.with
            ),
        ));
    }
    let mut only: BTreeSet<u32> = (from..=DEPLOY_TO).collect();
    only.insert(1);
    let again = Some(again(o, &plan, plan_flag));
    if o.dry_run || o.mock.is_some() {
        // Nothing runs, so nobody is asked; a hash that is given is still
        // checked, and so is whether the plan still matches what is there.
        if let Some(v) = approve_flag {
            approve(&plan, Some(v), &mut prompt::Nobody)?;
        }
        if o.mock.is_none() {
            still_holds(&plan.approved("flag"), Path::new(&work))?;
        }
        let mut s = Surface {
            resume: true,
            only: Some(only),
            stage: "deploy",
            again,
            ..Default::default()
        };
        return federate_with(
            repo,
            &Options {
                from,
                to: DEPLOY_TO,
                table: false,
                ..*o
            },
            &mut s,
        );
    }
    let approved = approve(&plan, approve_flag, ask)?;
    let mut s = Surface {
        resume: true,
        only: Some(only),
        stage: "deploy",
        plan: Some(approved),
        again,
        ..Default::default()
    };
    federate_with(
        repo,
        &Options {
            from,
            to: DEPLOY_TO,
            ..*o
        },
        &mut s,
    )
}

/// `goatbuilder federate test <partner>`: acceptance alone.
pub fn test(repo: &Path, o: &Options) -> Result<Report> {
    let again = Some(format!("goatbuilder federate test {}", o.with));
    let mut s = Surface {
        only: Some(BTreeSet::from([TEST])),
        stage: "test",
        again,
        ..Default::default()
    };
    federate_with(
        repo,
        &Options {
            from: TEST,
            to: TEST,
            ..*o
        },
        &mut s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federate::prompt::{Nobody, Scripted};

    fn code(e: &anyhow::Error) -> String {
        e.downcast_ref::<goat_errors::Coded>()
            .map(|c| c.code.clone())
            .unwrap_or_default()
    }

    /// A working folder with an agreement and one rendered file, and a plan
    /// made from them; returns the plan's body.
    fn made(d: &Path, extra: &str) -> String {
        std::fs::write(d.join("agreement.json"), "{}").unwrap();
        std::fs::create_dir_all(d.join("applied")).unwrap();
        std::fs::write(d.join("applied/edge.json5"), "r").unwrap();
        let body = format!(
            r#"{{"schema":"x/v1","peering":"xab","agreement_digest":"{}","artifacts":[{{"path":"applied/edge.json5","sha256":"{}"}}]{extra}}}"#,
            sha256_bytes(b"{}"),
            sha256_bytes(b"r")
        );
        std::fs::write(d.join("plan.json"), &body).unwrap();
        body
    }

    #[test]
    fn approval_binds_to_the_exact_hash_and_never_to_silence() {
        let d = tempfile::tempdir().unwrap();
        made(
            d.path(),
            r#","resources":[{"kind":"udp-port","scope":"edge-1","value":51821}]"#,
        );
        let plan = Plan::read(&d.path().join("plan.json")).unwrap();
        let spaced = groups(&plan.hash).split(": ").nth(1).unwrap().to_string();
        let a = approve(&plan, Some(&spaced), &mut Nobody).unwrap();
        assert_eq!(
            (a.how.as_str(), a.hash.as_str()),
            ("flag", plan.hash.as_str())
        );
        assert_eq!(a.resources, [Want::new("udp-port", "edge-1", "51821")]);
        assert_eq!(
            code(&approve(&plan, Some("sha256:00"), &mut Nobody).unwrap_err()),
            "GB-186"
        );
        let e = approve(&plan, None, &mut Nobody).unwrap_err();
        assert!(
            code(&e) == "GB-186" && e.to_string().contains(&plan.hash),
            "{e}"
        );
        for (answer, ok) in [("yes", true), ("y", false), ("", false)] {
            let mut sc = Scripted::new(&[answer]);
            assert_eq!(approve(&plan, None, &mut sc).is_ok(), ok, "{answer:?}");
            assert!(
                sc.transcript.contains(&plan.hash)
                    && sc.transcript.contains("udp-port 51821 on edge-1")
                    && sc.transcript.contains("applied/edge.json5"),
                "{}",
                sc.transcript
            );
        }
    }

    #[test]
    fn a_changed_plan_or_changed_inputs_need_a_new_plan() {
        let d = tempfile::tempdir().unwrap();
        let body = made(d.path(), "");
        let plan = Plan::read(&d.path().join("plan.json")).unwrap();
        let a = approve(&plan, Some(&plan.hash), &mut Nobody).unwrap();
        still_holds(&a, d.path()).expect("nothing changed");
        std::fs::write(d.path().join("applied/edge.json5"), "r2").unwrap();
        let e = still_holds(&a, d.path()).unwrap_err();
        assert!(
            code(&e) == "GB-188" && e.to_string().contains("edge.json5"),
            "{e}"
        );
        std::fs::write(d.path().join("applied/edge.json5"), "r").unwrap();
        // A rendered file the plan does not list is a change.
        std::fs::write(d.path().join("applied/extra.json5"), "x").unwrap();
        let e = still_holds(&a, d.path()).unwrap_err();
        assert!(
            e.to_string().contains("extra.json5 (not in the plan)"),
            "{e}"
        );
        std::fs::remove_file(d.path().join("applied/extra.json5")).unwrap();
        std::fs::write(d.path().join("agreement.json"), "{ }").unwrap();
        assert_eq!(code(&still_holds(&a, d.path()).unwrap_err()), "GB-188");
        std::fs::write(d.path().join("agreement.json"), "{}").unwrap();
        std::fs::write(d.path().join("plan.json"), format!("{body} ")).unwrap();
        assert_eq!(
            code(&still_holds(&a, d.path()).unwrap_err()),
            "GB-187",
            "the plan's bytes are what was approved"
        );
    }

    #[test]
    fn a_plan_that_does_not_say_what_it_was_made_from_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("plan.json");
        let refused = |body: &str| {
            std::fs::write(&p, body).unwrap();
            let e = Plan::read(&p).unwrap_err();
            assert_eq!(code(&e), "GB-187", "{body}: {e}");
            e.to_string()
        };
        assert_eq!(
            code(&Plan::read(&d.path().join("none.json")).unwrap_err()),
            "GB-187"
        );
        refused("{");
        assert!(refused(r#"{"peering":"xab"}"#).contains("agreement_digest"));
        let ag = sha256_bytes(b"{}");
        assert!(
            refused(&format!(r#"{{"peering":"xab","agreement_digest":"{ag}"}}"#))
                .contains("artifacts")
        );
        assert!(refused(&format!(
            r#"{{"peering":"xab","agreement_digest":"{ag}","artifacts":[]}}"#
        ))
        .contains("artifacts"));
        for path in [
            "/etc/passwd",
            "applied/../x",
            "../applied/x",
            "other/x",
            "applied",
        ] {
            let body = format!(
                r#"{{"peering":"xab","agreement_digest":"{ag}","artifacts":[{{"path":"{path}","sha256":"{ag}"}}]}}"#
            );
            assert!(refused(&body).contains("malformed artifacts[0]"), "{path}");
        }
        let typo = format!(
            r#"{{"peering":"xab","agreement_digest":"{ag}","artifacts":[{{"path":"applied/x","sha":"{ag}"}}]}}"#
        );
        assert!(refused(&typo).contains("malformed artifacts[0]"));
        let arts = format!(r#""artifacts":[{{"path":"applied/x","sha256":"{ag}"}}]"#);
        for r in [
            r#"[{"kind":"udp-port","scope":"edge-1","value":true}]"#,
            r#"[{"kind":"udp-port","value":1}]"#,
            r#"{"kind":"x"}"#,
        ] {
            let body =
                format!(r#"{{"peering":"xab","agreement_digest":"{ag}",{arts},"resources":{r}}}"#);
            refused(&body);
        }
    }
}
