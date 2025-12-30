use anyhow::{Context, Result};
use libqinit::storage_encryption::GOCRYPTFS_BINARY;
use log::{error, info};
use std::fs;

use libqinit::{OVERLAY_MOUNTPOINT, SYSTEM_HOME_DIR, rootfs, storage_encryption, system};
use openssl::pkey::PKey;
use openssl::pkey::Public;

const ADMIN_GROUP: &str = "wheel";

pub fn change_encryption_password(
    user: &str,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
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
    if new_password != storage_encryption::DISABLED_MODE_PASSWORD
        && fs::exists(&encryption_disabled_file_path)?
    {
        fs::remove_file(&encryption_disabled_file_path)?;
    }

    Ok(())
}

pub fn disable_encryption(user: &str, password: &str) -> Result<()> {
    change_encryption_password(
        &user,
        &password,
        &storage_encryption::DISABLED_MODE_PASSWORD,
    )?;
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

fn change_user_password_chroot_command(
    chroot_path: &str,
    user: &str,
    old_password: Option<&str>,
    new_password: &str,
    verify: bool,
) -> Result<()> {
    let passwd_path = "/usr/bin/passwd";
    if verify {
        if let Some(old_password) = old_password {
            system::run_command(
                "/usr/sbin/chroot",
                &[
                    &chroot_path,
                    "/bin/su",
                    "-s",
                    "/bin/sh",
                    "-c",
                    &format!(
                        "printf '{}\n{}\n{}' | {} {}",
                        &old_password, &new_password, &new_password, &passwd_path, &user
                    ),
                    &user,
                ],
            )
            .with_context(|| "Provided login credentials were incorrect")?;
        } else {
            return Err(anyhow::anyhow!("Please provide old password"));
        }
    } else {
        system::run_command(
            "/usr/sbin/chroot",
            &[
                &chroot_path,
                "/bin/sh",
                "-c",
                &format!(
                    "printf '{}\n{}' | {} {}",
                    &new_password, &new_password, &passwd_path, &user
                ),
            ],
        )
        .with_context(|| "Error setting password")?;
    }

    Ok(())
}

fn create_user_chroot_command(chroot_path: &str, username: &str, admin: bool) -> Result<()> {
    let useradd_path = "/usr/sbin/useradd";

    if admin {
        system::run_command(
            "/usr/sbin/chroot",
            &[
                &chroot_path,
                &useradd_path,
                "-M",
                "-G",
                &ADMIN_GROUP,
                &username,
            ],
        )?;
    } else {
        system::run_command(
            "/usr/sbin/chroot",
            &[&chroot_path, &useradd_path, "-M", &username],
        )?;
    }

    Ok(())
}

pub fn change_user_password(
    pubkey: &PKey<Public>,
    user: &str,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    info!(
        "Attempting to change system user password for user '{}'",
        &user
    );

    let handle_rootfs;
    if !system::is_mountpoint(&OVERLAY_MOUNTPOINT)? {
        rootfs::setup(&pubkey, true)?;
        handle_rootfs = true;
    } else {
        handle_rootfs = false;
    }

    let temporary_password = system::generate_random_string(128)?;
    info!("Temporary password is '{}'", &temporary_password);

    let mut do_error = false;
    info!("Setting temporary password for verification");
    if let Err(e) = change_user_password_chroot_command(
        &OVERLAY_MOUNTPOINT,
        &user,
        Some(&old_password),
        &temporary_password,
        true,
    ) {
        do_error = true;
        error!("{}", &e);
    } else {
        info!("Setting new requested password");
        if let Err(e) = change_user_password_chroot_command(
            &OVERLAY_MOUNTPOINT,
            &user,
            Some(&temporary_password),
            &new_password,
            false,
        ) {
            do_error = true;
            error!("{}", &e);
        }
    }

    if handle_rootfs {
        rootfs::tear_down()?;
    }

    if do_error {
        return Err(anyhow::anyhow!(
            "Failed to set new password for user '{}'",
            &user
        ));
    }

    Ok(())
}

fn initialize_encrypted_storage(path: &str, password: &str) -> Result<()> {
    system::run_command(
        "/bin/sh",
        &[
            "-c",
            &format!(
                "printf '{}\n{}' | {} -init {}",
                &password, &password, &GOCRYPTFS_BINARY, &path
            ),
        ],
    )
    .with_context(|| format!("Failed to initialize encrypted storage at path '{}'", &path))?;

    Ok(())
}

pub fn create(username: &str, password: &str, admin: bool) -> Result<()> {
    create_user_chroot_command(&OVERLAY_MOUNTPOINT, &username, admin)?;
    change_user_password_chroot_command(&OVERLAY_MOUNTPOINT, &username, None, &password, false)?;

    let home_dir_path = format!("{}/{}/{}", &OVERLAY_MOUNTPOINT, &SYSTEM_HOME_DIR, &username);
    let encrypted_home_dir_path = format!(
        "{}/{}/.{}",
        &OVERLAY_MOUNTPOINT, &SYSTEM_HOME_DIR, &username
    );
    fs::create_dir_all(&encrypted_home_dir_path)?;
    fs::create_dir_all(&home_dir_path)?;

    initialize_encrypted_storage(&encrypted_home_dir_path, &password)?;
    storage_encryption::mount_storage(&username, &password)?;

    rootfs::run_chroot_command(&[
        "/bin/sh",
        "-c",
        &format!(
            "/bin/cp -r /etc/skel/.* /{}/{}",
            &SYSTEM_HOME_DIR, &username
        ),
    ])?;
    rootfs::run_chroot_command(&[
        "/usr/sbin/chown",
        "-R",
        &format!("{}:{}", &username, &username),
        &format!("/{}/{}", &SYSTEM_HOME_DIR, &username),
    ])?;

    storage_encryption::unmount_storage(&username)?;

    Ok(())
}
