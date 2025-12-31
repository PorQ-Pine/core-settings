use anyhow::{Context, Result};
use libqinit::{
    boot_config::BootConfig, rootfs::run_chroot_command, storage_encryption::GOCRYPTFS_BINARY,
};
use log::{error, info};
use std::{
    fs,
    sync::{Arc, Mutex},
};

use libqinit::{OVERLAY_MOUNTPOINT, SYSTEM_HOME_DIR, rootfs, storage_encryption, system};
use openssl::pkey::PKey;
use openssl::pkey::Public;

const ADMIN_GROUP: &str = "wheel";

pub enum AdminLoginStatus {
    Success,
    Failure,
    NotAdmin,
}

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
    pubkey: Option<&PKey<Public>>,
    user: &str,
    old_password: &str,
    new_password: Option<&str>,
) -> Result<()> {
    info!(
        "Attempting to change system user password for user '{}'",
        &user
    );

    let handle_rootfs;
    if !system::is_mountpoint(&OVERLAY_MOUNTPOINT)? {
        if let Some(pubkey) = pubkey {
            rootfs::setup(&pubkey, true)?;
        } else {
            return Err(anyhow::anyhow!("Cannot extract public key"));
        }
        handle_rootfs = true;
    } else {
        handle_rootfs = false;
    }

    let mut shadow_backup: Option<String> = None;
    let mut shadow_file_path: Option<String> = None;
    let new_password_string;

    if let Some(password) = new_password {
        new_password_string = password;
    } else {
        shadow_file_path = Some(format!("{}/etc/shadow", &OVERLAY_MOUNTPOINT));
        if let Some(path) = shadow_file_path.clone() {
            shadow_backup = Some(
                fs::read_to_string(&path)
                    .with_context(|| "Failed to backup shadow file from overlay filesystem")?,
            );
        }
        new_password_string = old_password;
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
            &new_password_string,
            false,
        ) {
            do_error = true;
            error!("{}", &e);
        }
    }

    if let Some(backup) = shadow_backup {
        if let Some(path) = shadow_file_path {
            fs::write(&path, &backup)
                .with_context(|| "Failed to write shadow file backup to overlay filesystem")?;
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

pub fn set_default_user(user: &str, boot_config: Arc<Mutex<BootConfig>>) -> Result<()> {
    info!("Setting default user to '{}'", &user);
    boot_config.lock().unwrap().system.default_user = Some(user.to_string());

    Ok(())
}

pub fn is_admin(user: &str) -> bool {
    if let Err(_) = run_chroot_command(&[
        "/bin/sh",
        "-c",
        &format!(
            "/usr/sbin/groups '{}' | /usr/sbin/grep -q '{}'",
            &user, &ADMIN_GROUP
        ),
    ]) {
        return false;
    } else {
        return true;
    }
}

pub fn admin_login_verify(username: &str, password: &str) -> AdminLoginStatus {
    if !is_admin(&username) {
        return AdminLoginStatus::NotAdmin;
    }

    if let Err(_) = change_user_password(None, &username, &password, None) {
        return AdminLoginStatus::Failure;
    } else {
        return AdminLoginStatus::Success;
    }
}

pub fn create(
    username: &str,
    password: &str,
    admin: bool,
    make_default: bool,
    boot_config: Arc<Mutex<BootConfig>>,
) -> Result<()> {
    if username.contains(".") || username.contains("/") {
        return Err(anyhow::anyhow!("Username contains forbidden characters"));
    }

    create_user_chroot_command(&OVERLAY_MOUNTPOINT, &username, admin)
        .with_context(|| "Failed to create UNIX user in chroot")?;
    change_user_password_chroot_command(&OVERLAY_MOUNTPOINT, &username, None, &password, false)
        .with_context(|| "Failed to set new UNIX user's password")?;

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
    ])
    .with_context(|| "Failed to copy skeleton directory file(s) to new user's home directory")?;
    rootfs::run_chroot_command(&[
        "/usr/sbin/chown",
        "-R",
        &format!("{}:{}", &username, &username),
        &format!("/{}/{}", &SYSTEM_HOME_DIR, &username),
    ])
    .with_context(|| "Failed to set filesystem permissions")?;

    storage_encryption::unmount_storage(&username)
        .with_context(|| "Failed to unmount encrypted storage")?;

    if make_default {
        set_default_user(&username, boot_config).with_context(|| "Failed to set default user")?
    }

    Ok(())
}

pub fn delete(user: &str) -> Result<()> {
    if !user.is_empty() {
        let home_dir_path = format!("{}/{}/{}", &OVERLAY_MOUNTPOINT, &SYSTEM_HOME_DIR, &user);
        let encrypted_home_dir_path =
            format!("{}/{}/.{}", &OVERLAY_MOUNTPOINT, &SYSTEM_HOME_DIR, &user);

        fs::remove_dir_all(&home_dir_path)
            .with_context(|| "Failed to remove user's home directory")?;
        fs::remove_dir_all(&encrypted_home_dir_path)
            .with_context(|| "Failed to remove user's encrypted home directory")?;

        run_chroot_command(&["/usr/sbin/userdel", "-f", "-r", &user])
            .with_context(|| "Failed to remove UNIX user from overlay filesystem")?;
    } else {
        return Err(anyhow::anyhow!("No username provided"));
    }

    Ok(())
}
