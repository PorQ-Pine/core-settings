use libqinit::storage_encryption;

use crate::gui_fn::error_toast;
use crate::{CoreSettings, SystemUser, SettingsPage};
use slint::SharedString;

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
