use std::path::Path;

use anyhow::{Context, Result, bail};
use keyring::{Entry, Error};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEYRING_SERVICE: &str = "com.cliptown.desktop.history";

pub fn read_or_create_database_key(path: &Path) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let account = keyring_account(path)?;
    let entry = Entry::new(KEYRING_SERVICE, &account)
        .context("initialize operating-system credential store")?;
    match entry.get_secret() {
        Ok(secret) => parse_key(secret),
        Err(Error::NoEntry) if path.exists() => {
            bail!("encrypted history key is missing; refusing destructive recovery")
        }
        Err(Error::NoEntry) => {
            let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
            getrandom::fill(key.as_mut()).context("generate encrypted history key")?;
            entry
                .set_secret(key.as_ref())
                .context("store encrypted history key")?;
            Ok(key)
        }
        Err(error) => Err(error).context("read encrypted history key"),
    }
}

fn parse_key(secret: Vec<u8>) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let secret = Zeroizing::new(secret);
    if secret.len() != KEY_BYTES {
        bail!("encrypted history key has an invalid length")
    }
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(secret.as_slice());
    Ok(key)
}

fn keyring_account(path: &Path) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for history key")?
            .join(path)
    };
    let digest = Sha256::digest(absolute.to_string_lossy().as_bytes());
    Ok(format!("history-{}", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_identifier_does_not_expose_the_local_path() -> Result<()> {
        let account = keyring_account(Path::new("private/clipboard.db"))?;
        assert!(account.starts_with("history-"));
        assert_eq!(account.len(), "history-".len() + 64);
        assert!(!account.contains("private"));
        Ok(())
    }
}
