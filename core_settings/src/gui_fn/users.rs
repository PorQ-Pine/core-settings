use std::rc::Rc;
use libqinit::storage_encryption::DISABLED_MODE_PASSWORD;
use log::info;

use libqinit::{rootfs, storage_encryption};

use crate::gui_fn::{error_toast, toast};
use crate::{CoreSettings, SettingsPage, SystemUser};
use openssl::pkey::{PKey, Public};
use slint::{SharedString, Timer, TimerMode, Weak};

pub fn get_users(gui: &CoreSettings) {
    match storage_encryption::get_users_using_storage_encryption() {
        Ok(users_using_storage_encryption) => {
            let users_shared_string_vec: Vec<SharedString> = users_using_storage_encryption
                .iter()
                .map(|user| SharedString::from(user))
                .collect();
            gui.set_users(slint::ModelRc::new(slint::VecModel::from(
                users_shared_string_vec,
            )));
        }
        Err(e) => {
            error_toast(&gui, "Failed to get users list", e.into());
            gui.set_settings_page(SettingsPage::None);
        }
    }
}

pub fn get_user_details(gui: &CoreSettings, user: SharedString) {
    match storage_encryption::get_encryption_user_details(&user) {
        Ok(details) => gui.set_selected_user(SystemUser {
            encryption: details.encryption_enabled,
            name: user,
            encrypted_key: SharedString::from(&details.encrypted_key),
            salt: SharedString::from(&details.salt),
        }),
        Err(e) => {
            gui.set_selected_user(SystemUser {
                // Default to false if there is an error, I guess
                encryption: false,
                name: user,
                encrypted_key: SharedString::new(),
                salt: SharedString::new(),
            });
            error_toast(&gui, "Failed to get user's details", e.into())
        }
    }
}

pub fn change_user_password(
    gui_weak: Weak<CoreSettings>,
    user: SharedString,
    mut old_password: SharedString,
    new_password: SharedString,
    encrypted_storage_was_disabled: bool,
    pubkey: &PKey<Public>,
    timer: &Rc<Timer>,
) {
    info!("{} {} {}", &user, &old_password, &new_password);
    let gui_weak = gui_weak.clone();
    let pubkey = pubkey.clone();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        move || {
            if let Some(gui) = gui_weak.upgrade() {
                if encrypted_storage_was_disabled {
                    old_password = SharedString::from(storage_encryption::DISABLED_MODE_PASSWORD);
                }

                if let Err(e) =
                    rootfs::change_user_password(&pubkey, &user, &old_password, &new_password)
                {
                    error_toast(&gui, "Failed to change user password", e.into());
                } else {
                    if let Err(e) = libcoresettings::users::change_password(
                        &user.to_string(),
                        &old_password.to_string(),
                        &new_password.to_string(),
                    ) {
                        error_toast(&gui, "Failed to change encryption password", e.into());
                    } else {
                        toast(&gui, "Password set successfully");
                    }
                }
                refresh_users_ui(&gui);
            }
        },
    );
}

pub fn disable_storage_encryption(
    gui_weak: Weak<CoreSettings>,
    user: SharedString,
    password: SharedString,
    pubkey: &PKey<Public>,
    timer: &Rc<Timer>,
) {
    let gui_weak = gui_weak.clone();
    let pubkey = pubkey.clone();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        move || {
            if let Some(gui) = gui_weak.upgrade() {
                if let Err(e) =
                    rootfs::change_user_password(&pubkey, &user, &password.to_string(), &DISABLED_MODE_PASSWORD)
                {
                    error_toast(&gui, "Failed to change user password", e.into());
                }

                if let Err(e) = libcoresettings::users::disable_encryption(&user.to_string(), &password.to_string())
                {
                    error_toast(&gui, "Failed to disable encryption", e.into());
                } else {
                    toast(&gui, "Encryption successfully disabled");
                }
                refresh_users_ui(&gui);
            }
        },
    );
}

fn refresh_users_ui(gui: &CoreSettings) {
    gui.invoke_get_users();
    gui.invoke_get_selected_user_details(gui.get_selected_user().name);
}
