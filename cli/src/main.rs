use abe_authorities::{Claim, AuthorityRegistry};
use abe_audit::AuditLog;
use abe_core::codec;
use abe_core::keys::{MasterSecret, PublicParams, UserSecretKey};
use abe_core::{register_attribute, AccessTree};
use abe_envelope::{open as envelope_open, seal as envelope_seal};
use abe_revocation::RevocationList;
use abe_storage::PackageStore;
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "secure-abe", about = "Ciphertext-policy attribute-based access control over encrypted files")]
struct Cli {
    /// Directory holding all system state for this deployment.
    #[arg(long, global = true, default_value = "./data")]
    data: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initializes a fresh deployment: generates the master secret and
    /// public parameters, and creates an empty authority registry.
    Setup,

    /// Registers a named attribute authority and the attribute-key
    /// prefixes it is allowed to issue (e.g. "department", "clearance").
    RegisterAuthority {
        #[arg(long)]
        name: String,
        /// Comma separated list of attribute-key prefixes. Empty = unrestricted.
        #[arg(long, default_value = "")]
        controls: String,
    },

    /// Issues a decryption key for a user, from one authority, for a
    /// set of attribute claims.
    Issue {
        #[arg(long)]
        authority: String,
        #[arg(long)]
        user: String,
        /// Boolean/flag claim, e.g. --flag role=admin (repeatable).
        #[arg(long = "flag")]
        flags: Vec<String>,
        /// Text claim key=value, e.g. --text department=security (repeatable).
        #[arg(long = "text")]
        texts: Vec<String>,
        /// Numeric claim key=value:max, e.g. --numeric clearance=5:10 (repeatable).
        #[arg(long = "numeric")]
        numerics: Vec<String>,
    },

    /// Encrypts a file under an access-tree policy.
    Encrypt {
        #[arg(long)]
        file: PathBuf,
        /// Policy expression, e.g. "(department=security AND clearance>=4) OR role=admin"
        #[arg(long)]
        policy: String,
    },

    /// Decrypts a previously encrypted package for a given user, if
    /// that user's issued key satisfies the package's policy.
    Decrypt {
        #[arg(long)]
        id: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        out: PathBuf,
    },

    /// Lists stored encrypted packages.
    List,

    /// Prints the audit log.
    Audit,

    /// Bumps the revocation epoch for an attribute. Future issuance and
    /// encryption use the new epoch; already-issued keys and
    /// already-encrypted documents at the old epoch are unaffected (see
    /// the abe-revocation crate docs).
    RevokeAttribute {
        #[arg(long)]
        attribute: String,
    },

    /// Marks a user as revoked for future issuance. Does not invalidate
    /// keys already issued to that user.
    RevokeUser {
        #[arg(long)]
        user: String,
    },

    /// Runs the Ali / Sara / Reza / Admin walkthrough end to end in a
    /// throwaway directory, printing each step's result.
    Demo,
}

fn setup_path(data: &Path) -> PathBuf {
    data.join("setup.json")
}
fn authorities_path(data: &Path) -> PathBuf {
    data.join("authorities.json")
}
fn revocation_path(data: &Path) -> PathBuf {
    data.join("revocation.json")
}
fn audit_path(data: &Path) -> PathBuf {
    data.join("audit.log")
}
fn keys_dir(data: &Path) -> PathBuf {
    data.join("keys")
}
fn packages_dir(data: &Path) -> PathBuf {
    data.join("packages")
}

fn load_setup(data: &Path) -> Result<(PublicParams, MasterSecret)> {
    let s = fs::read_to_string(setup_path(data))
        .with_context(|| "no setup found; run `secure-abe setup` first")?;
    Ok(codec::setup_bundle_from_json(&s).map_err(|e| anyhow!(e.to_string()))?)
}

fn save_setup(data: &Path, pp: &PublicParams, msk: &MasterSecret) -> Result<()> {
    fs::write(setup_path(data), codec::setup_bundle_to_json(pp, msk))?;
    Ok(())
}

fn load_registry(data: &Path) -> Result<AuthorityRegistry> {
    let path = authorities_path(data);
    if !path.exists() {
        return Ok(AuthorityRegistry::new());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn save_registry(data: &Path, reg: &AuthorityRegistry) -> Result<()> {
    fs::write(authorities_path(data), serde_json::to_string_pretty(reg)?)?;
    Ok(())
}

fn load_user_key(data: &Path, user: &str) -> Result<UserSecretKey> {
    let path = keys_dir(data).join(format!("{user}.json"));
    let s = fs::read_to_string(&path)
        .with_context(|| format!("no key on file for user '{user}'; run `issue` first"))?;
    Ok(codec::user_key_from_json(&s).map_err(|e| anyhow!(e.to_string()))?)
}

fn save_user_key(data: &Path, user: &str, usk: &UserSecretKey) -> Result<()> {
    fs::create_dir_all(keys_dir(data))?;
    fs::write(
        keys_dir(data).join(format!("{user}.json")),
        codec::user_key_to_json(usk),
    )?;
    Ok(())
}

fn retag_tree(tree: &AccessTree, revocation: &RevocationList) -> AccessTree {
    match tree {
        AccessTree::Leaf(a) => AccessTree::Leaf(revocation.tag(a)),
        AccessTree::Gate {
            threshold,
            children,
        } => AccessTree::Gate {
            threshold: *threshold,
            children: children.iter().map(|c| retag_tree(c, revocation)).collect(),
        },
    }
}

fn parse_claims(flags: &[String], texts: &[String], numerics: &[String]) -> Result<Vec<Claim>> {
    let mut claims = Vec::new();
    for f in flags {
        claims.push(Claim::Flag(f.clone()));
    }
    for t in texts {
        let (k, v) = t
            .split_once('=')
            .ok_or_else(|| anyhow!("--text must be key=value, got '{t}'"))?;
        claims.push(Claim::Text {
            key: k.to_string(),
            value: v.to_string(),
        });
    }
    for n in numerics {
        let (kv, max) = n
            .split_once(':')
            .ok_or_else(|| anyhow!("--numeric must be key=value:max, got '{n}'"))?;
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--numeric must be key=value:max, got '{n}'"))?;
        claims.push(Claim::Numeric {
            key: k.to_string(),
            value: v.parse().with_context(|| format!("bad numeric value in '{n}'"))?,
            max: max.parse().with_context(|| format!("bad numeric max in '{n}'"))?,
        });
    }
    Ok(claims)
}

fn cmd_setup(data: &Path) -> Result<()> {
    fs::create_dir_all(data)?;
    let mut rng = rand::thread_rng();
    let (pp, msk) = abe_core::setup(&mut rng);
    save_setup(data, &pp, &msk)?;
    save_registry(data, &AuthorityRegistry::new())?;
    PackageStore::open(packages_dir(data))?;
    let audit = AuditLog::open(audit_path(data));
    audit.record(abe_audit::AuditEvent::new(
        "system",
        "SETUP",
        "-",
        "generated master secret and public parameters",
    ))?;
    println!("Initialized a new deployment at {}", data.display());
    println!("WARNING: setup.json contains the master secret. In production, keep it in an HSM or isolated authority process, never in a shared filesystem.");
    Ok(())
}

fn cmd_register_authority(data: &Path, name: &str, controls: &str) -> Result<()> {
    let mut reg = load_registry(data)?;
    let controls: Vec<String> = controls
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    reg.register(name, controls.clone());
    save_registry(data, &reg)?;
    println!("Registered authority '{name}' controlling: {}", if controls.is_empty() { "*".to_string() } else { controls.join(", ") });
    Ok(())
}

fn cmd_issue(
    data: &Path,
    authority: &str,
    user: &str,
    flags: &[String],
    texts: &[String],
    numerics: &[String],
) -> Result<()> {
    let (mut pp, msk) = load_setup(data)?;
    let registry = load_registry(data)?;
    let revocation = RevocationList::open(revocation_path(data))?;
    let audit = AuditLog::open(audit_path(data));

    if let Ok(rev) = fs::read_to_string(revocation_path(data)) {
        if rev.contains(&format!("\"{user}\"")) {
            // best-effort human hint; the authoritative check is below
        }
    }
    let rev_check = RevocationList::open(revocation_path(data))?;
    if rev_check.is_user_revoked(user) {
        bail!("user '{user}' has been revoked and cannot be issued new keys");
    }

    let claims = parse_claims(flags, texts, numerics)?;

    let mut rng = rand::thread_rng();
    let mut flat_attrs = Vec::new();
    for claim in &claims {
        registry
            .check_permission(authority, claim)
            .map_err(|e| anyhow!(e.to_string()))?;
        for a in claim.resolve() {
            let tagged = revocation.tag(&a);
            register_attribute(&mut pp, &tagged, &mut rng);
            flat_attrs.push(tagged);
        }
    }

    // A single user secret key ties every attribute component together
    // with one random `r` (see abe-core::scheme docs) — that binding is
    // what makes an AND-policy across attributes from different
    // authorities work, and it means a fresh `issue` call cannot simply
    // append to a previously issued key file: the whole key, old
    // attributes included, has to be re-minted together under a new
    // `r`. This reference implementation therefore merges attribute
    // *names* from any existing key on file with the newly granted
    // ones and re-runs keygen once over the union. Note this implies a
    // single logical key-issuing process shared by all named
    // authorities (they contribute claims, not independent key
    // material) — true decentralized multi-authority ABE, where each
    // authority holds its own independent secret, needs a GID-tied
    // construction (e.g. Lewko-Waters) that is out of scope here.
    if let Ok(existing) = load_user_key(data, user) {
        for a in existing.attribute_names() {
            if !flat_attrs.contains(&a) {
                flat_attrs.push(a);
            }
        }
    }

    let usk = abe_core::keygen(&pp, &msk, user, &flat_attrs, &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;

    save_setup(data, &pp, &msk)?; // persist any newly registered attributes
    save_user_key(data, user, &usk)?;

    audit.record(abe_audit::AuditEvent::new(
        authority,
        "ISSUE_KEY",
        user,
        &format!("attributes={}", flat_attrs.join(",")),
    ))?;

    println!("Issued key for '{user}' with attributes:");
    for a in &flat_attrs {
        println!("  - {a}");
    }
    Ok(())
}

fn cmd_encrypt(data: &Path, file: &Path, policy: &str) -> Result<()> {
    let (mut pp, msk) = load_setup(data)?;
    let revocation = RevocationList::open(revocation_path(data))?;
    let audit = AuditLog::open(audit_path(data));

    let raw_tree = abe_policy::parse(policy).map_err(|e| anyhow!(e.to_string()))?;
    let tree = retag_tree(&raw_tree, &revocation);

    let mut rng = rand::thread_rng();
    for leaf in tree.leaves() {
        register_attribute(&mut pp, leaf, &mut rng);
    }
    save_setup(data, &pp, &msk)?;

    let plaintext = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let package = envelope_seal(&pp, &plaintext, &tree, policy, &mut rng)
        .map_err(|e| anyhow!(e.to_string()))?;

    let store = PackageStore::open(packages_dir(data))?;
    let filename = file
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "document".to_string());
    let id = store.put(&filename, &package)?;

    audit.record(abe_audit::AuditEvent::new(
        "system",
        "ENCRYPT",
        &id,
        &format!("file={filename} policy={policy}"),
    ))?;

    println!("Encrypted '{}' as package {id}", file.display());
    println!("Policy: {policy}");
    Ok(())
}

fn cmd_decrypt(data: &Path, id: &str, user: &str, out: &Path) -> Result<()> {
    let (pp, _msk) = load_setup(data)?;
    let usk = load_user_key(data, user)?;
    let store = PackageStore::open(packages_dir(data))?;
    let audit = AuditLog::open(audit_path(data));
    let package = store.get(id)?;

    match envelope_open(&pp, &usk, &package) {
        Ok(plaintext) => {
            fs::write(out, &plaintext)?;
            audit.record(abe_audit::AuditEvent::new(
                user,
                "DECRYPT_SUCCESS",
                id,
                &format!("wrote {}", out.display()),
            ))?;
            println!("Access granted. Wrote {}", out.display());
            Ok(())
        }
        Err(e) => {
            audit.record(abe_audit::AuditEvent::new(
                user,
                "DECRYPT_DENIED",
                id,
                &e.to_string(),
            ))?;
            println!("ACCESS DENIED for '{user}' on package {id}: policy not satisfied");
            Err(anyhow!(e.to_string()))
        }
    }
}

fn cmd_list(data: &Path) -> Result<()> {
    let store = PackageStore::open(packages_dir(data))?;
    let packages = store.list()?;
    if packages.is_empty() {
        println!("No packages stored yet.");
    }
    for p in packages {
        println!("{}  file={}  policy=\"{}\"", p.id, p.original_filename, p.policy_summary);
    }
    Ok(())
}

fn cmd_audit(data: &Path) -> Result<()> {
    let audit = AuditLog::open(audit_path(data));
    for e in audit.read_all()? {
        println!(
            "[{}] actor={} action={} subject={} detail={}",
            e.timestamp_unix, e.actor, e.action, e.subject, e.detail
        );
    }
    Ok(())
}

fn cmd_revoke_attribute(data: &Path, attribute: &str) -> Result<()> {
    let mut revocation = RevocationList::open(revocation_path(data))?;
    let audit = AuditLog::open(audit_path(data));
    let epoch = revocation.revoke_attribute(attribute)?;
    audit.record(abe_audit::AuditEvent::new(
        "system",
        "REVOKE_ATTRIBUTE",
        attribute,
        &format!("new_epoch={epoch}"),
    ))?;
    println!("Attribute '{attribute}' moved to epoch {epoch}.");
    println!("Reminder: existing keys/ciphertexts at the previous epoch are unaffected until reissued/re-encrypted.");
    Ok(())
}

fn cmd_revoke_user(data: &Path, user: &str) -> Result<()> {
    let mut revocation = RevocationList::open(revocation_path(data))?;
    let audit = AuditLog::open(audit_path(data));
    revocation.revoke_user(user)?;
    audit.record(abe_audit::AuditEvent::new(
        "system",
        "REVOKE_USER",
        user,
        "blocked from future key issuance",
    ))?;
    println!("User '{user}' blocked from future key issuance. Their existing key (if any) is not retroactively invalidated.");
    Ok(())
}

fn cmd_demo() -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("secure-abe-demo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;
    println!("Running end-to-end demo in {}", tmp.display());
    println!();

    cmd_setup(&tmp)?;
    cmd_register_authority(&tmp, "hr", "department")?;
    cmd_register_authority(&tmp, "security", "clearance,role")?;
    println!();

    cmd_issue(&tmp, "hr", "ali", &[], &["department=security".into()], &[])?;
    cmd_issue(&tmp, "security", "ali", &[], &[], &["clearance=5:10".into()])?;
    println!();

    cmd_issue(&tmp, "hr", "sara", &[], &["department=marketing".into()], &[])?;
    cmd_issue(&tmp, "security", "sara", &[], &[], &["clearance=2:10".into()])?;
    println!();

    cmd_issue(&tmp, "hr", "reza", &[], &["department=security".into()], &[])?;
    cmd_issue(&tmp, "security", "reza", &[], &[], &["clearance=3:10".into()])?;
    println!();

    cmd_issue(&tmp, "security", "admin1", &["role=admin".into()], &[], &[])?;
    println!();

    let doc = tmp.join("incident-report.txt");
    fs::write(&doc, b"Top secret incident report contents.")?;
    cmd_encrypt(
        &tmp,
        &doc,
        "(department=security AND clearance>=4) OR role=admin",
    )?;
    println!();

    let store = PackageStore::open(packages_dir(&tmp))?;
    let id = store.list()?.first().expect("just encrypted one").id.clone();

    for user in ["ali", "sara", "reza", "admin1"] {
        let out = tmp.join(format!("{user}-attempt.txt"));
        println!("--- {user} attempts to decrypt ---");
        let _ = cmd_decrypt(&tmp, &id, user, &out);
        println!();
    }

    println!("Demo audit trail:");
    cmd_audit(&tmp)?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Setup => cmd_setup(&cli.data),
        Command::RegisterAuthority { name, controls } => {
            cmd_register_authority(&cli.data, name, controls)
        }
        Command::Issue {
            authority,
            user,
            flags,
            texts,
            numerics,
        } => cmd_issue(&cli.data, authority, user, flags, texts, numerics),
        Command::Encrypt { file, policy } => cmd_encrypt(&cli.data, file, policy),
        Command::Decrypt { id, user, out } => cmd_decrypt(&cli.data, id, user, out),
        Command::List => cmd_list(&cli.data),
        Command::Audit => cmd_audit(&cli.data),
        Command::RevokeAttribute { attribute } => cmd_revoke_attribute(&cli.data, attribute),
        Command::RevokeUser { user } => cmd_revoke_user(&cli.data, user),
        Command::Demo => cmd_demo(),
    }
}
