use anyhow::{Context, Result};

use libqinit::storage_encryption;
use libqinit::system;
use std::fs;

pub fn change_password(user: &str, old_password: &str, new_password: &str) -> Result<()> {
    system::run_command(
        "/bin/sh",
        &[
            "-c",
            &format!(
                "printf '{}\n{}' | {} -passwd {}/{}/.{}",
                &old_password,
                &new_password,
                &storage_encryption::GOCRYPTFS_BINARY,
                &libqinit::MAIN_PART_MOUNTPOINT,
                &libqinit::SYSTEM_HOME_DIR,
                &user
            ),
        ],
    )
    .with_context(|| {
        format!(
            "Failed to change encrypted storage's password for user '{}'",
            &user
        )
    })?;

    let encryption_disabled_file_path = format!(
        "{}/{}/.{}/{}",
        &libqinit::MAIN_PART_MOUNTPOINT,
        &libqinit::SYSTEM_HOME_DIR,
        &user,
        &storage_encryption::DISABLED_MODE_FILE
    );
    if new_password != storage_encryption::DISABLED_MODE_PASSWORD && fs::exists(&encryption_disabled_file_path)? {
        fs::remove_file(&encryption_disabled_file_path)?;
    }

    Ok(())
}

pub fn disable_encryption(user: &str, password: &str) -> Result<()> {
    change_password(&user, &password, &storage_encryption::DISABLED_MODE_PASSWORD)?;
    fs::File::create(&format!(
        "{}/{}/.{}/{}",
        &libqinit::MAIN_PART_MOUNTPOINT,
        &libqinit::SYSTEM_HOME_DIR,
        &user,
        &storage_encryption::DISABLED_MODE_FILE,
    ))
    .with_context(|| {
        format!(
            "Failed to create file disabling encryption for user '{}'",
            &user
        )
    })?;

    Ok(())
}

pub fn create(user: &str, password: &str, admin: bool) -> Result<()> {
    Ok(())
}
