use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use paper_pgp::{
    backup::{self, Backup, ENTROPY_LEN, Entropy, WORD_COUNT},
    master, paper,
};
use sequoia_openpgp::serialize::SerializeInto;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Recoverable OpenPGP master keys with 22-word paper backups"
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
    /// Unix seconds for exact recovery, rounded down to a multiple of 1024; default: now.
    #[arg(long)]
    created_at: Option<u32>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Hex,
    Binary,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new backup from operating-system randomness, or from entropy you supply.
    Generate {
        /// Entropy file ('-' reads stdin): at least 160 bits, e.g. coin flips, condensed
        /// with Argon2id. Without it, 160 bits of operating-system randomness are used.
        #[arg(long)]
        from: Option<String>,
        /// Digit format of the --from file.
        #[arg(long, value_enum, default_value = "hex", requires = "from")]
        format: Format,
        /// ADVANCED: use exactly 160 bits from --from verbatim, without Argon2id.
        #[arg(long, requires = "from")]
        exact: bool,
        #[command(flatten)]
        creation: Creation,
        #[command(flatten)]
        output: Output,
    },
    /// Validate words; output the stored entropy in hex and metadata on stderr.
    Decode {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        output: Output,
    },
    /// Export the recovered master key: into a saved certificate, or as a fresh certificate.
    Export {
        #[command(flatten)]
        input: Input,
        /// Saved public certificate to restore the secret into; nothing is signed.
        #[arg(long, conflicts_with_all = ["identity", "expires", "public"])]
        certificate: Option<String>,
        /// User ID for a fresh certification-only certificate, e.g. 'Alice <alice@example.org>'.
        #[arg(long, required_unless_present = "certificate")]
        identity: Option<String>,
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
    /// Output a blank, self-contained Typst A5 template.
    Template {
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
    const LIMIT: usize = 1024 * 1024;
    // Fixed storage also holds the byte used to detect an oversized input.
    let mut bytes = Zeroizing::new(vec![0; LIMIT + 1]);
    let mut reader: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path).with_context(|| format!("cannot open {path}"))?)
    };
    let mut length = 0;
    while length < bytes.len() {
        match reader.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(length <= LIMIT, "input exceeds 1 MiB limit");
    bytes.truncate(length);
    Ok(bytes)
}

fn text(bytes: &[u8]) -> Result<&str> {
    let text = std::str::from_utf8(bytes).context("input must be UTF-8 text")?;
    // Editors on some platforms prepend a byte order mark.
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text))
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
        // A failed write must not leave a partial file behind: existing files
        // are never overwritten, so it would also block the retry.
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error).with_context(|| format!("cannot write {path}"));
        }
    }
    Ok(())
}

fn metadata(backup: &Backup) {
    eprintln!(
        "Version: {}; created-at: {}; words: {}",
        backup.version(),
        backup.created_at(),
        WORD_COUNT
    );
}

fn store_new(secret: Entropy, creation: Creation, output: Output) -> Result<()> {
    let backup = match creation.created_at {
        Some(time) => Backup::new(secret, time),
        None => Backup::new_now(secret)?,
    };
    write_output(&output.output, backup.encode().as_bytes())?;
    metadata(&backup);
    Ok(())
}

fn separate_stdin(paths: &[Option<&str>]) -> Result<()> {
    ensure!(
        paths.iter().filter(|path| **path == Some("-")).count() <= 1,
        "only one of the words, the passphrase, and the certificate can read stdin"
    );
    Ok(())
}

fn serialize_secret(value: &impl SerializeInto) -> Result<Zeroizing<Vec<u8>>> {
    // The library provides an upper bound; a slice writer cannot reallocate.
    let mut bytes = Zeroizing::new(vec![0; SerializeInto::serialized_len(value)]);
    let length = SerializeInto::serialize_into(value, &mut bytes)?;
    bytes.truncate(length);
    Ok(bytes)
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            from,
            format,
            exact,
            creation,
            output,
        } => {
            let secret = match from {
                None => backup::random()?,
                Some(path) => {
                    let binary = matches!(format, Format::Binary);
                    let bytes = read_input(&path)?;
                    if exact {
                        eprintln!(
                            "WARNING: exact entropy is for advanced users; its quality is your responsibility."
                        );
                        backup::parse_exact(text(&bytes)?, binary)?
                    } else {
                        eprintln!(
                            "Provide high-entropy digits: a KDF cannot create missing entropy."
                        );
                        backup::derive(text(&bytes)?, binary)?
                    }
                }
            };
            store_new(secret, creation, output)?;
        }
        Command::Decode { input, output } => {
            let bytes = read_input(&input.input)?;
            let backup = Backup::decode(text(&bytes)?)?;
            let hex_len = ENTROPY_LEN * 2;
            let mut result = Zeroizing::new(vec![b'\n'; hex_len + 1]);
            hex::encode_to_slice(backup.secret(), &mut result[..hex_len])?;
            write_output(&output.output, &result)?;
            metadata(&backup);
        }
        Command::Export {
            input,
            certificate,
            identity,
            passphrase_file,
            unprotected,
            public,
            expires,
            output,
        } => {
            separate_stdin(&[
                Some(input.input.as_str()),
                passphrase_file.as_deref(),
                certificate.as_deref(),
            ])?;
            let bytes = read_input(&input.input)?;
            let backup = Backup::decode(text(&bytes)?)?;
            // OpenPGP stores whole seconds; truncate so printed and stored times agree.
            let now =
                UNIX_EPOCH + Duration::from_secs(u64::from(backup::timestamp(SystemTime::now())?));
            let expires_at = expires
                .map(|validity| now.checked_add(validity).context("expiry is out of range"))
                .transpose()?;
            // Expiry is a relative u32 period and may extend beyond Unix u32 time.
            let expiry_seconds = expires_at
                .map(|at| at.duration_since(UNIX_EPOCH).map(|d| d.as_secs()))
                .transpose()?;
            let mut cert = match (&certificate, &identity) {
                (Some(path), _) => master::restore(&backup, &read_input(path)?)?,
                (None, Some(identity)) => master::certificate(&backup, identity, now, expires_at)?,
                (None, None) => unreachable!("clap requires --identity or --certificate"),
            };
            if let Some(path) = passphrase_file {
                cert = master::protect(cert, &read_password(&path)?)?;
            } else if unprotected {
                eprintln!("WARNING: exporting an unprotected secret master key.");
            }
            let result = if public {
                serialize_secret(&cert.armored())?
            } else {
                serialize_secret(&cert.as_tsk().armored())?
            };
            write_output(&output.output, &result)?;
            eprintln!("Primary fingerprint: {}", cert.fingerprint());
            if certificate.is_some() {
                eprintln!(
                    "Restored into the saved certificate: {} user IDs, {} subkeys, nothing signed",
                    cert.userids().count(),
                    cert.keys().subkeys().count()
                );
            } else {
                match expiry_seconds {
                    Some(seconds) => eprintln!("Key expires: {seconds} (Unix seconds)"),
                    None => eprintln!("Key expires: never"),
                }
            }
        }
        Command::Template { output } => write_output(&output.output, paper::template().as_bytes())?,
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
