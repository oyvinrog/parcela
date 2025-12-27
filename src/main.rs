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
    use parcela::virtual_drive::VirtualDrive;
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

    #[test]
    fn virtual_drive_encrypt_split_combine_roundtrip() {
        // Create a virtual drive
        let drive = VirtualDrive::new_with_id(
            "test-drive-001".to_string(),
            "Test Drive".to_string(),
            32,
        );

        // Encode the drive
        let encoded = drive.encode().expect("encode");

        // Encrypt the encoded drive
        let password = "secure_password";
        let encrypted = parcela::encrypt(&encoded, password).expect("encrypt");

        // Split into shares
        let shares = parcela::split_shares(&encrypted).expect("split");
        assert_eq!(shares.len(), 3);

        // Combine any two shares
        let combined = parcela::combine_shares(&[shares[0].clone(), shares[2].clone()])
            .expect("combine");

        // Decrypt
        let decrypted = parcela::decrypt(&combined, password).expect("decrypt");

        // Decode and verify
        let recovered_drive = VirtualDrive::decode(&decrypted).expect("decode");
        assert_eq!(recovered_drive.metadata.id, "test-drive-001");
        assert_eq!(recovered_drive.metadata.name, "Test Drive");
        assert_eq!(recovered_drive.metadata.size_mb, 32);
    }

    #[test]
    fn virtual_drive_with_content_roundtrip() {
        // Create a virtual drive with content
        let mut drive = VirtualDrive::new_with_id(
            "content-drive".to_string(),
            "Content Test".to_string(),
            16,
        );
        drive.content = b"simulated filesystem data".to_vec();

        // Full encrypt-split-combine-decrypt cycle
        let password = "test123";
        let encoded = drive.encode().expect("encode");
        let encrypted = parcela::encrypt(&encoded, password).expect("encrypt");
        let shares = parcela::split_shares(&encrypted).expect("split");

        // Use shares 1 and 2 this time
        let combined = parcela::combine_shares(&[shares[0].clone(), shares[1].clone()])
            .expect("combine");
        let decrypted = parcela::decrypt(&combined, password).expect("decrypt");
        let recovered = VirtualDrive::decode(&decrypted).expect("decode");

        assert_eq!(recovered.content, b"simulated filesystem data");
    }

    #[test]
    fn virtual_drive_shares_saved_to_files() {
        let dir = temp_dir("vdrive-shares");

        // Create and encode a virtual drive
        let drive = VirtualDrive::new_with_id(
            "file-test".to_string(),
            "File Test Drive".to_string(),
            8,
        );
        let encoded = drive.encode().expect("encode");
        let encrypted = parcela::encrypt(&encoded, "pass").expect("encrypt");
        let shares = parcela::split_shares(&encrypted).expect("split");

        // Save shares to files
        let base_name = "test.vdrive";
        let mut share_paths = Vec::new();
        for share in shares.iter() {
            let filename = format!("{}.share{}", base_name, share.index);
            let path = dir.join(&filename);
            let data = parcela::encode_share(share);
            fs::write(&path, data).expect("write share");
            share_paths.push(path);
        }

        // Read shares back from files
        let data1 = fs::read(&share_paths[0]).expect("read share1");
        let data2 = fs::read(&share_paths[2]).expect("read share3");
        let s1 = parcela::decode_share(&data1).expect("decode share1");
        let s2 = parcela::decode_share(&data2).expect("decode share3");

        // Combine and decrypt
        let combined = parcela::combine_shares(&[s1, s2]).expect("combine");
        let decrypted = parcela::decrypt(&combined, "pass").expect("decrypt");
        let recovered = VirtualDrive::decode(&decrypted).expect("decode");

        assert_eq!(recovered.metadata.id, "file-test");
        assert_eq!(recovered.metadata.name, "File Test Drive");
    }

    #[test]
    fn virtual_drive_wrong_password_fails() {
        let drive = VirtualDrive::new("Secure Drive".to_string(), 64);
        let encoded = drive.encode().expect("encode");
        let encrypted = parcela::encrypt(&encoded, "correct").expect("encrypt");
        let shares = parcela::split_shares(&encrypted).expect("split");

        let combined = parcela::combine_shares(&[shares[0].clone(), shares[1].clone()])
            .expect("combine");

        let result = parcela::decrypt(&combined, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn virtual_drive_single_share_fails() {
        let drive = VirtualDrive::new("Single Share Test".to_string(), 16);
        let encoded = drive.encode().expect("encode");
        let encrypted = parcela::encrypt(&encoded, "pass").expect("encrypt");
        let shares = parcela::split_shares(&encrypted).expect("split");

        // Trying to combine with just one share should fail
        let result = parcela::combine_shares(&[shares[0].clone()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least two shares"));
    }
}
