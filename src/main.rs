use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use parcela::{
    combine_shares, decode_share, decrypt, encode_share, encrypt, split_shares, Share,
};

#[derive(Parser)]
#[command(name = "parcela", version, about = "Split AES-256 encrypted files into 2-of-3 shares")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Split {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long)]
        password: String,
    },
    Combine {
        #[arg(long, required = true, num_args = 2..=3)]
        shares: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Split {
            input,
            out_dir,
            password,
        } => split_cmd(&input, &out_dir, &password)?,
        Command::Combine {
            shares,
            output,
            password,
        } => combine_cmd(&shares, &output, &password)?,
    }

    Ok(())
}

fn split_cmd(input: &Path, out_dir: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input)?;
    let encrypted = encrypt(&plaintext, password)?;
    let shares = split_shares(&encrypted)?;

    fs::create_dir_all(out_dir)?;
    let base_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");

    for share in shares.iter() {
        let filename = format!("{base_name}.share{}", share.index);
        let path = out_dir.join(filename);
        let data = encode_share(share);
        fs::write(path, data)?;
    }

    Ok(())
}

fn combine_cmd(
    share_paths: &[PathBuf],
    output: &Path,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut shares: Vec<Share> = Vec::with_capacity(share_paths.len());
    for path in share_paths {
        let data = fs::read(path)?;
        let share = decode_share(&data)?;
        shares.push(share);
    }

    let encrypted = combine_shares(&shares)?;
    let plaintext = decrypt(&encrypted, password)?;
    fs::write(output, plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("parcela-{name}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn split_then_combine_roundtrip() {
        let dir = temp_dir("roundtrip");
        let input = dir.join("note.txt");
        let out_dir = dir.join("shares");
        let output = dir.join("recovered.txt");
        let content = b"tauri roundtrip";
        fs::write(&input, content).expect("write input");

        split_cmd(&input, &out_dir, "pass").expect("split");

        let share1 = out_dir.join("note.txt.share1");
        let share3 = out_dir.join("note.txt.share3");
        assert!(share1.exists());
        assert!(share3.exists());

        combine_cmd(&[share1, share3], &output, "pass").expect("combine");
        let recovered = fs::read(&output).expect("read output");
        assert_eq!(recovered, content);
    }

    #[test]
    fn combine_requires_two_shares() {
        let dir = temp_dir("combine");
        let input = dir.join("note.txt");
        let out_dir = dir.join("shares");
        let output = dir.join("recovered.txt");
        fs::write(&input, b"data").expect("write input");

        split_cmd(&input, &out_dir, "pass").expect("split");
        let share1 = out_dir.join("note.txt.share1");

        let err = combine_cmd(&[share1], &output, "pass").unwrap_err();
        assert!(
            err.to_string().contains("need at least two shares"),
            "unexpected error: {err}"
        );
    }
}
