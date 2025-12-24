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
