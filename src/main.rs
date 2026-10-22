use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use gpg_keys::{
    backup::{self, Backup, BackupSecret, SecretKind},
    master, paper,
};
use sequoia_openpgp::serialize::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Recoverable OpenPGP master keys with 35-word compact or 44-word raw backups"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Output {
    /// New output file; '-' writes to stdout. Files are never overwritten.
    #[arg(short, long, default_value = "-")]
    output: String,
}

#[derive(Args)]
struct Input {
    /// Input file; '-' reads stdin. Avoid secrets in command-line arguments.
    #[arg(short, long, default_value = "-")]
    input: String,
}

#[derive(Args)]
struct Creation {
    /// Unix seconds for exact recovery; default: the current time.
    #[arg(long)]
    created_at: Option<u32>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Hex,
    Binary,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Compact,
    Raw,
}
impl From<Kind> for SecretKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Compact => Self::CompactEntropy,
            Kind::Raw => Self::Raw,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate 160 bits of OS entropy as a 35-word compact backup.
    Random {
        #[command(flatten)]
        creation: Creation,
        #[command(flatten)]
        output: Output,
    },
    /// Derive compact entropy using Argon2id from at least 160 high-entropy bits.
    Derive {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        creation: Creation,
        #[command(flatten)]
        output: Output,
    },
    /// ADVANCED: encode exact compact entropy (160 bits) or a raw Ed25519 seed (256 bits).
    Encode {
        #[command(flatten)]
        input: Input,
        #[arg(long, value_enum, default_value = "hex")]
        format: Format,
        #[arg(long, value_enum, default_value = "compact")]
        kind: Kind,
        #[command(flatten)]
        creation: Creation,
        #[command(flatten)]
        output: Output,
    },
    /// Validate words; output the stored secret in hex and metadata on stderr.
    Decode {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        output: Output,
    },
    /// Import an existing v4/algorithm-22 Ed25519 master secret as a raw backup.
    Import {
        #[command(flatten)]
        input: Input,
        /// Passphrase file for an encrypted secret-key export; '-' reads stdin.
        #[arg(long)]
        passphrase_file: Option<String>,
        #[command(flatten)]
        output: Output,
    },
    /// Restore a certification-only Ed25519 master key as ASCII-armored OpenPGP.
    Export {
        #[command(flatten)]
        input: Input,
        /// Full User ID, e.g. 'Alice <alice@example.org>'.
        #[arg(long)]
        identity: String,
        /// File with an export passphrase (one final LF or CRLF is removed).
        #[arg(long, conflicts_with_all = ["unprotected", "public"], required_unless_present_any = ["unprotected", "public"])]
        passphrase_file: Option<String>,
        /// Explicitly export a secret key without passphrase protection.
        #[arg(long, conflicts_with = "public")]
        unprotected: bool,
        /// Export only the public certificate.
        #[arg(long)]
        public: bool,
        /// Key validity from now, GnuPG style: <n>d, <n>w, <n>m (30 days), or <n>y (365 days).
        #[arg(long, value_parser = master::validity)]
        expires: Option<Duration>,
        #[command(flatten)]
        output: Output,
    },
    /// Output a blank, self-contained Typst A5 template for the selected variant.
    Template {
        #[arg(long, value_enum, default_value = "compact")]
        kind: Kind,
        #[command(flatten)]
        output: Output,
    },
    /// Output the pinned 1024-word list, in zero-based index order.
    Wordlist {
        #[command(flatten)]
        output: Output,
    },
}

fn read_input(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let reader: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path).with_context(|| format!("cannot open {path}"))?)
    };
    reader.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "input exceeds 1 MiB limit");
    Ok(bytes)
}

fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).context("input must be UTF-8 text")
}

fn read_password(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut password = read_input(path)?;
    if password.ends_with(b"\n") {
        password.pop();
        if password.ends_with(b"\r") {
            password.pop();
        }
    }
    ensure!(!password.is_empty(), "passphrase must not be empty");
    Ok(password)
}

fn write_output(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()?;
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).with_context(|| {
            format!("cannot create {path} (existing files are never overwritten)")
        })?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

fn metadata(backup: &Backup) {
    eprintln!(
        "Variant: {}; created-at: {}; words: {}",
        backup.kind().name(),
        backup.created_at(),
        backup.word_count()
    );
}

fn store_new(secret: BackupSecret, creation: Creation, output: Output) -> Result<()> {
    let backup = match creation.created_at {
        Some(time) => Backup::new(secret, time),
        None => Backup::new_now(secret)?,
    };
    write_output(&output.output, backup.encode().as_bytes())?;
    metadata(&backup);
    Ok(())
}

fn separate_stdin(input: &Input, password: &Option<String>) -> Result<()> {
    ensure!(
        password.as_deref() != Some("-") || input.input != "-",
        "key material and passphrase cannot both read stdin"
    );
    Ok(())
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Random { creation, output } => store_new(backup::random()?, creation, output)?,
        Command::Derive {
            input,
            creation,
            output,
        } => {
            eprintln!("Provide high-entropy bits: a KDF cannot create missing entropy.");
            let bytes = read_input(&input.input)?;
            store_new(backup::derive(text(&bytes)?)?, creation, output)?;
        }
        Command::Encode {
            input,
            format,
            kind,
            creation,
            output,
        } => {
            eprintln!(
                "WARNING: exact-secret input is for advanced users; its entropy is your responsibility."
            );
            let bytes = read_input(&input.input)?;
            store_new(
                backup::parse_exact(text(&bytes)?, matches!(format, Format::Binary), kind.into())?,
                creation,
                output,
            )?;
        }
        Command::Decode { input, output } => {
            let bytes = read_input(&input.input)?;
            let backup = Backup::decode(text(&bytes)?)?;
            let mut result = Zeroizing::new(hex::encode(backup.secret().payload()));
            result.push('\n');
            write_output(&output.output, result.as_bytes())?;
            metadata(&backup);
        }
        Command::Import {
            input,
            passphrase_file,
            output,
        } => {
            separate_stdin(&input, &passphrase_file)?;
            let bytes = read_input(&input.input)?;
            let password = passphrase_file.as_deref().map(read_password).transpose()?;
            let backup = master::import(&bytes, password.as_ref().map(|p| p.as_slice()))?;
            write_output(&output.output, backup.encode().as_bytes())?;
            metadata(&backup);
            eprintln!(
                "Primary fingerprint: {}",
                master::certificate(&backup, "Imported master key", backup.creation_time(), None)?
                    .fingerprint()
            );
        }
        Command::Export {
            input,
            identity,
            passphrase_file,
            unprotected,
            public,
            expires,
            output,
        } => {
            separate_stdin(&input, &passphrase_file)?;
            let bytes = read_input(&input.input)?;
            let backup = Backup::decode(text(&bytes)?)?;
            // OpenPGP stores whole seconds; truncate so printed and stored times agree.
            let now =
                UNIX_EPOCH + Duration::from_secs(u64::from(backup::timestamp(SystemTime::now())?));
            let expires_at = expires.map(|validity| now + validity);
            let mut cert = master::certificate(&backup, &identity, now, expires_at)?;
            if let Some(path) = passphrase_file {
                cert = master::protect(cert, &read_password(&path)?)?;
            } else if unprotected {
                eprintln!("WARNING: exporting an unprotected secret master key.");
            }
            let mut result = Zeroizing::new(Vec::new());
            if public {
                cert.armored().serialize(&mut *result)?;
            } else {
                cert.as_tsk().armored().serialize(&mut *result)?;
            }
            write_output(&output.output, &result)?;
            eprintln!("Primary fingerprint: {}", cert.fingerprint());
            match expires_at {
                Some(at) => eprintln!("Key expires: {} (Unix seconds)", backup::timestamp(at)?),
                None => eprintln!("Key expires: never"),
            }
        }
        Command::Template { kind, output } => {
            write_output(&output.output, paper::template(kind.into()).as_bytes())?
        }
        Command::Wordlist { output } => write_output(&output.output, backup::WORDLIST.as_bytes())?,
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}
