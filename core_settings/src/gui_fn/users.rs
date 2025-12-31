use std::{
    rc::Rc,
    sync::{Arc, Mutex, mpsc::Sender},
};

use libcoresettings::users::{AdminLoginStatus, is_admin};
use libqinit::{
    boot_config::BootConfig,
    storage_encryption::{self, DISABLED_MODE_PASSWORD},
};

use crate::gui_fn::{error_toast, toast};
use crate::{CoreSettings, SettingsPage, SystemUser};
use slint::{SharedString, Timer, TimerMode, Weak};

const FAILED_ADMIN_STATUS_TOGGLE: &str = "Failed to change administrator status";

pub fn get_users(gui: &CoreSettings, boot_config: Arc<Mutex<BootConfig>>) {
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

    if let Some(user) = boot_config.lock().unwrap().system.default_user.clone() {
        gui.set_default_user(SharedString::from(user))
    } else {
        gui.set_default_user(SharedString::from(String::new()))
    }
}

pub fn get_user_details(gui: &CoreSettings, user: SharedString) {
    match storage_encryption::get_encryption_user_details(&user) {
        Ok(details) => gui.set_selected_user(SystemUser {
            encryption: details.encryption_enabled,
            name: user.clone(),
            encrypted_key: SharedString::from(&details.encrypted_key),
            salt: SharedString::from(&details.salt),
            admin: is_admin(&user.clone().to_string()),
        }),
        Err(e) => {
            gui.set_selected_user(SystemUser {
                // Default to false if there is an error, I guess
                encryption: false,
                name: user.clone(),
                encrypted_key: SharedString::new(),
                salt: SharedString::new(),
                admin: is_admin(&user.clone().to_string()),
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
    timer: &Rc<Timer>,
    boot_config: Arc<Mutex<BootConfig>>,
) {
    let gui_weak = gui_weak.clone();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        {
            let boot_config = boot_config.clone();
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    if encrypted_storage_was_disabled {
                        old_password =
                            SharedString::from(storage_encryption::DISABLED_MODE_PASSWORD);
                    }

                    if let Err(e) = libcoresettings::users::change_user_password(
                        None,
                        &user,
                        &old_password,
                        Some(&new_password),
                    ) {
                        error_toast(&gui, "Failed to change user password", e.into());
                    } else {
                        if let Err(e) = libcoresettings::users::change_encryption_password(
                            &user.to_string(),
                            &old_password.to_string(),
                            &new_password.to_string(),
                        ) {
                            error_toast(&gui, "Failed to change encryption password", e.into());
                        } else {
                            toast(&gui, "Password set successfully");
                        }
                    }
                    refresh_users_ui(&gui, boot_config.clone());
                }
            }
        },
    );
}

pub fn disable_storage_encryption(
    gui_weak: Weak<CoreSettings>,
    user: SharedString,
    password: SharedString,
    timer: &Rc<Timer>,
    boot_config: Arc<Mutex<BootConfig>>,
) {
    let gui_weak = gui_weak.clone();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        {
            let boot_config = boot_config.clone();
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    if let Err(e) = libcoresettings::users::change_user_password(
                        None,
                        &user,
                        &password.to_string(),
                        Some(&DISABLED_MODE_PASSWORD),
                    ) {
                        error_toast(&gui, "Failed to change user password", e.into());
                    }

                    if let Err(e) = libcoresettings::users::disable_encryption(
                        &user.to_string(),
                        &password.to_string(),
                    ) {
                        error_toast(&gui, "Failed to disable encryption", e.into());
                    } else {
                        toast(&gui, "Encryption successfully disabled");
                    }
                    refresh_users_ui(&gui, boot_config.clone());
                }
            }
        },
    );
}

pub fn create(
    gui_weak: Weak<CoreSettings>,
    username: SharedString,
    password: SharedString,
    admin: bool,
    make_default: bool,
    timer: &Rc<Timer>,
    quit_sender: Sender<()>,
    quit_afterwards: bool,
    boot_config: Arc<Mutex<BootConfig>>,
) {
    let gui_weak = gui_weak.clone();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        {
            let boot_config = boot_config.clone();
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    if let Err(e) = libcoresettings::users::create(
                        &username,
                        &password,
                        admin,
                        make_default,
                        boot_config.clone(),
                    ) {
                        error_toast(&gui, "Failed to create user", e.into());
                    } else if quit_afterwards {
                        let _ = quit_sender.send(());
                    } else {
                        gui.set_admin_lock_set(false);
                        refresh_users_ui(&gui, boot_config.clone());
                        gui.set_sticky_toast(false);
                        toast(&gui, "User created successfully");
                    }
                }
            }
        },
    )
}

pub fn admin_login_verify(
    gui_weak: Weak<CoreSettings>,
    username: &str,
    password: &str,
    timer: &Rc<Timer>,
) {
    let gui_weak = gui_weak.clone();
    let username = username.to_owned();
    let password = password.to_owned();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        {
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    match libcoresettings::users::admin_login_verify(&username, &password) {
                        AdminLoginStatus::Success => {
                            gui.set_admin_lock_set(false);
                            toast(&gui, "Login successful");
                        }
                        AdminLoginStatus::NotAdmin => toast(&gui, "Administrator user not found"),
                        AdminLoginStatus::Failure => toast(&gui, "Login failed"),
                    }
                }
            }
        },
    )
}

pub fn delete(
    gui_weak: Weak<CoreSettings>,
    user: &str,
    timer: &Rc<Timer>,
    boot_config: Arc<Mutex<BootConfig>>,
) {
    let gui_weak = gui_weak.clone();
    let user = user.to_owned();
    timer.start(
        TimerMode::SingleShot,
        std::time::Duration::from_millis(100),
        {
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    if let Err(e) = libcoresettings::users::delete(&user) {
                        error_toast(&gui, "Failed to delete user", e.into());
                    } else {
                        toast(&gui, "User deleted successfully");
                    }
                    gui.set_selected_user(SystemUser {
                        admin: false,
                        encrypted_key: SharedString::from(String::new()),
                        encryption: false,
                        name: SharedString::from(String::new()),
                        salt: SharedString::from(String::new()),
                    });
                    refresh_users_ui(&gui, boot_config.clone());
                }
            }
        },
    );
}

pub fn make_admin(gui_weak: Weak<CoreSettings>, user: &str, boot_config: Arc<Mutex<BootConfig>>) {
    if let Some(gui) = gui_weak.upgrade() {
        if let Err(e) = libcoresettings::users::change_admin_status(&user, true) {
            error_toast(&gui, &FAILED_ADMIN_STATUS_TOGGLE, e.into());
        }
        refresh_users_ui(&gui, boot_config.clone());
    }
}

pub fn remove_admin(gui_weak: Weak<CoreSettings>, user: &str, boot_config: Arc<Mutex<BootConfig>>) {
    if let Some(gui) = gui_weak.upgrade() {
        if sufficient_number_of_admin_users_remaining(&gui) {
            if let Err(e) = libcoresettings::users::change_admin_status(&user, false) {
                error_toast(&gui, &FAILED_ADMIN_STATUS_TOGGLE, e.into());
            }
            refresh_users_ui(&gui, boot_config.clone());
        } else {
            toast(&gui, "At least one administrator required");
        }
    }
}

pub fn set_default(gui_weak: Weak<CoreSettings>, user: &str, boot_config: Arc<Mutex<BootConfig>>) {
    if let Some(gui) = gui_weak.upgrade() {
        if user.is_empty() {
            libcoresettings::users::set_default(None, boot_config.clone());
        } else {
            libcoresettings::users::set_default(Some(&user), boot_config.clone());
        }
        refresh_users_ui(&gui, boot_config.clone());
    }
}

fn sufficient_number_of_admin_users_remaining(gui: &CoreSettings) -> bool {
    match libcoresettings::users::count_admin_users() {
        Ok(count) => return count >= 2,
        Err(e) => {
            error_toast(&gui, "Failed to count admin users", e.into());
            return false;
        }
    };
}

fn refresh_users_ui(gui: &CoreSettings, boot_config: Arc<Mutex<BootConfig>>) {
    get_users(&gui, boot_config);

    let selected_user = gui.get_selected_user();
    if !selected_user.name.is_empty() {
        get_user_details(&gui, selected_user.name);
    }
}
