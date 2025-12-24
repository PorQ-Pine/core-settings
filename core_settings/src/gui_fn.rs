use crate::{CoreSettings, DialogType};
use slint::SharedString;

use anyhow;
use log::error;

pub mod users;

pub const TOAST_DURATION_MILLIS: i32 = 5000;
pub const TOAST_GC_DELAY: i32 = 100;

pub fn toast_timer_loop_check(gui: &CoreSettings) {
    if gui.get_dialog() == DialogType::Toast {
        if !gui.get_sticky_toast() {
            let current_count = gui.get_dialog_millis_count();
            let future_count = current_count + TOAST_GC_DELAY;
            if future_count > TOAST_DURATION_MILLIS {
                gui.set_dialog_millis_count(0);
                gui.set_dialog(DialogType::None);
            } else {
                gui.set_dialog_millis_count(future_count);
            }
        }
    }
}

pub fn error_toast(gui: &CoreSettings, message: &str, e: anyhow::Error) {
    gui.set_sticky_toast(false);
    gui.set_dialog_message(SharedString::from(message));
    gui.set_dialog(DialogType::Toast);
    error!("{}: {}", &message, e);
}
