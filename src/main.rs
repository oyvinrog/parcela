use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use parcela::{
    combine_shares, decrypt, encode_share, encrypt, split_shares, Share,
    stego::{encode_share_as_image, decode_share_universal, detect_share_format},
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
        /// Generate shares as PNG images with embedded steganographic data
        #[arg(long, default_value = "true")]
        image: bool,
        /// Use legacy binary format instead of image format
        #[arg(long)]
        legacy: bool,
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
            image,
            legacy,
        } => {
            let use_image = image && !legacy;
            split_cmd(&input, &out_dir, &password, use_image)?
        }
        Command::Combine {
            shares,
            output,
            password,
        } => combine_cmd(&shares, &output, &password)?,
    }

    Ok(())
}

fn split_cmd(input: &Path, out_dir: &Path, password: &str, use_image: bool) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input)?;
    let encrypted = encrypt(&plaintext, password)?;
    let shares = split_shares(&encrypted)?;

    fs::create_dir_all(out_dir)?;
    let base_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");

    // Use a seed based on the input filename for consistent image selection
    let seed: u64 = base_name.bytes().fold(0u64, |acc, b| acc.wrapping_add(b as u64).wrapping_mul(31));

    for share in shares.iter() {
        if use_image {
            // Generate share as PNG image with embedded steganographic data
            let filename = format!("{base_name}.share{}.png", share.index);
            let path = out_dir.join(filename);
            let data = encode_share_as_image(share, Some(seed))?;
            fs::write(path, data)?;
        } else {
            // Generate legacy binary share
            let filename = format!("{base_name}.share{}", share.index);
            let path = out_dir.join(filename);
            let data = encode_share(share);
            fs::write(path, data)?;
        }
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
        // Use universal decoder that handles stego images, v2, and legacy v1 formats
        let format = detect_share_format(&data).unwrap_or("unknown");
        eprintln!("Reading share from {:?} (format: {})", path.file_name().unwrap_or_default(), format);
        let share = decode_share_universal(&data)?;
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

        // Test with legacy format (non-image)
        split_cmd(&input, &out_dir, "pass", false).expect("split");

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

        split_cmd(&input, &out_dir, "pass", false).expect("split");
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

    #[test]
    fn split_then_combine_image_shares() {
        let dir = temp_dir("image-shares");
        let input = dir.join("secret.txt");
        let out_dir = dir.join("shares");
        let output = dir.join("recovered.txt");
        let content = b"steganography test content";
        fs::write(&input, content).expect("write input");

        // Split with image shares (default behavior)
        split_cmd(&input, &out_dir, "testpass", true).expect("split");

        // Verify PNG files were created
        let share1 = out_dir.join("secret.txt.share1.png");
        let share2 = out_dir.join("secret.txt.share2.png");
        let share3 = out_dir.join("secret.txt.share3.png");
        assert!(share1.exists(), "share1.png should exist");
        assert!(share2.exists(), "share2.png should exist");
        assert!(share3.exists(), "share3.png should exist");

        // Verify files start with PNG signature
        let data1 = fs::read(&share1).expect("read share1");
        assert_eq!(&data1[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "should be valid PNG");

        // Combine any two image shares
        combine_cmd(&[share1, share3], &output, "testpass").expect("combine");
        let recovered = fs::read(&output).expect("read output");
        assert_eq!(recovered, content);
    }

    #[test]
    fn backward_compat_reads_legacy_and_image() {
        // Test backward compatibility: verify we can read both legacy and image shares
        let dir = temp_dir("compat-shares");
        let input = dir.join("compat.txt");
        let content = b"backward compatibility test";
        fs::write(&input, content).expect("write input");

        // Create legacy shares
        let legacy_dir = dir.join("legacy");
        split_cmd(&input, &legacy_dir, "compatpass", false).expect("split legacy");
        
        // Combine legacy shares
        let legacy_share1 = legacy_dir.join("compat.txt.share1");
        let legacy_share2 = legacy_dir.join("compat.txt.share2");
        let legacy_output = dir.join("recovered_legacy.txt");
        combine_cmd(&[legacy_share1.clone(), legacy_share2], &legacy_output, "compatpass").expect("combine legacy");
        let recovered_legacy = fs::read(&legacy_output).expect("read legacy output");
        assert_eq!(recovered_legacy, content, "legacy shares should recover content");

        // Create image shares
        let image_dir = dir.join("image");
        split_cmd(&input, &image_dir, "compatpass", true).expect("split image");
        
        // Combine image shares  
        let image_share1 = image_dir.join("compat.txt.share1.png");
        let image_share2 = image_dir.join("compat.txt.share2.png");
        let image_output = dir.join("recovered_image.txt");
        combine_cmd(&[image_share1, image_share2], &image_output, "compatpass").expect("combine image");
        let recovered_image = fs::read(&image_output).expect("read image output");
        assert_eq!(recovered_image, content, "image shares should recover content");
    }

    #[test]
    fn stego_share_is_valid_png() {
        use parcela::stego;

        let share = parcela::Share {
            index: 1,
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let png_data = stego::encode_share_as_image(&share, None).expect("encode");
        
        // Verify PNG signature
        assert_eq!(&png_data[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        
        // Verify we can decode it back
        let decoded = stego::decode_share_from_image(&png_data).expect("decode");
        assert_eq!(decoded.index, share.index);
        assert_eq!(decoded.payload, share.payload);
    }

    #[test]
    fn detect_share_formats() {
        use parcela::stego;

        // Test stego format detection
        let share = parcela::Share {
            index: 1,
            payload: vec![10, 20, 30],
        };
        
        let stego_data = stego::encode_share_as_image(&share, None).expect("encode stego");
        assert_eq!(stego::detect_share_format(&stego_data), Some("stego"));
        
        let legacy_data = parcela::encode_share(&share);
        assert_eq!(stego::detect_share_format(&legacy_data), Some("v2"));
        
        // Random data should be unrecognized
        assert_eq!(stego::detect_share_format(b"random data"), None);
    }
}
