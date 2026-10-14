use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use gpg_keys::{backup, master, paper};
use sequoia_openpgp::serialize::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Recoverable OpenPGP certification keys with 40-word paper backups"
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
    /// Input file; '-' reads stdin. Avoid entering secrets as command-line arguments.
    #[arg(short, long, default_value = "-")]
    input: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Hex,
    Binary,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a random 256-bit seed and encode it as 40 words.
    Random {
        #[command(flatten)]
        output: Output,
    },
    /// Derive a seed using Argon2id from at least 256 high-entropy binary digits.
    Derive {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        output: Output,
    },
    /// ADVANCED: encode an exact 256-bit seed; its entropy is your responsibility.
    Encode {
        #[command(flatten)]
        input: Input,
        #[arg(long, value_enum, default_value = "hex")]
        format: Format,
        #[command(flatten)]
        output: Output,
    },
    /// Validate 40 words and output the exact seed in hexadecimal.
    Decode {
        #[command(flatten)]
        input: Input,
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
        #[command(flatten)]
        output: Output,
    },
    /// Output a self-contained Typst A5 template, instructions, and full wordlist.
    Template {
        #[command(flatten)]
        output: Output,
    },
    /// Output the pinned 1024-word list, in index order (zero-based).
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

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Random { output } => write_output(
            &output.output,
            backup::encode(&backup::random()?).as_bytes(),
        )?,
        Command::Derive { input, output } => {
            eprintln!("Provide high-entropy bits: a KDF cannot create missing entropy.");
            let bytes = read_input(&input.input)?;
            write_output(
                &output.output,
                backup::encode(&backup::derive(text(&bytes)?)?).as_bytes(),
            )?;
        }
        Command::Encode {
            input,
            format,
            output,
        } => {
            eprintln!(
                "WARNING: exact-seed input is for advanced users; the seed must already have sufficient entropy."
            );
            let bytes = read_input(&input.input)?;
            let secret = backup::parse_exact(text(&bytes)?, matches!(format, Format::Binary))?;
            write_output(&output.output, backup::encode(&secret).as_bytes())?;
        }
        Command::Decode { input, output } => {
            let bytes = read_input(&input.input)?;
            let secret = backup::decode(text(&bytes)?)?;
            let mut result = Zeroizing::new(hex::encode(secret.as_ref()));
            result.push('\n');
            write_output(&output.output, result.as_bytes())?;
        }
        Command::Export {
            input,
            identity,
            passphrase_file,
            unprotected,
            public,
            output,
        } => {
            ensure!(
                passphrase_file.as_deref() != Some("-") || input.input != "-",
                "mnemonic and passphrase cannot both read stdin"
            );
            let bytes = read_input(&input.input)?;
            let secret = backup::decode(text(&bytes)?)?;
            let mut cert = master::certificate(&secret, &identity)?;
            if let Some(path) = passphrase_file {
                let mut password = read_input(&path)?;
                if password.ends_with(b"\n") {
                    password.pop();
                    if password.ends_with(b"\r") {
                        password.pop();
                    }
                }
                cert = master::protect(cert, &password)?;
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
