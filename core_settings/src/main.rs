use std::{process::exit, rc::Rc};

use anyhow::{Context, Result};
use libqinit::boot_config::BootConfig;
use log::info;
use slint::{Timer, TimerMode};
slint::include_modules!();

mod gui_fn;

fn main() -> Result<()> {
    env_logger::init();
    info!("Core Settings initializing");

    let pubkey = libqinit::signing::read_public_key()?;

    // Boot configuration
    // We ignore boot configuration validity checks, since issues related
    // to the former should already have been handled by qinit beforehand.
    let (mut boot_config, _) = BootConfig::read()?;

    // GUI
    let gui = CoreSettings::new().with_context(|| "Failed to initialize Slint UI")?;
    let gui_weak = gui.as_weak();

    let toast_gc_timer = Timer::default();
    toast_gc_timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_millis(gui_fn::TOAST_GC_DELAY as u64),
        {
            let gui_weak = gui_weak.clone();
            move || {
                if let Some(gui) = gui_weak.upgrade() {
                    gui_fn::toast_timer_loop_check(&gui);
                }
            }
        },
    );

    // OOBE
    if !boot_config.flags.first_boot_done {
        gui.set_page(Page::OOBE);
    }

    // Control panels
    gui.on_get_users({
        let gui_weak = gui_weak.clone();
        move || {
            if let Some(gui) = gui_weak.upgrade() {
                gui_fn::users::get_users(&gui)
            }
        }
    });

    gui.on_get_selected_user_details({
        let gui_weak = gui_weak.clone();
        move |user| {
            if let Some(gui) = gui_weak.upgrade() {
                gui_fn::users::get_user_details(&gui, user)
            }
        }
    });

    let encryption_change_password_timer = Rc::new(Timer::default());
    gui.on_change_user_password({
        let gui_weak = gui_weak.clone();
        let pubkey = pubkey.clone();
        move |user, old_password, new_password, encrypted_storage_was_disabled| {
            gui_fn::users::change_user_password(
                gui_weak.clone(),
                user,
                old_password,
                new_password,
                encrypted_storage_was_disabled,
                &pubkey,
                &encryption_change_password_timer,
            )
        }
    });

    let encryption_disable_timer = Rc::new(Timer::default());
    gui.on_disable_storage_encryption({
        let gui_weak = gui_weak.clone();
        let pubkey = pubkey.clone();
        move |user, password| {
            gui_fn::users::disable_storage_encryption(
                gui_weak.clone(),
                user,
                password,
                &pubkey,
                &encryption_disable_timer,
            );
        }
    });

    gui.on_create_user({
        let gui_weak = gui_weak.clone();
        move |username, password, admin| {
            gui_fn::users::create(gui_weak.clone(), username, password, admin);
        }
    });

    // Virtual keyboard
    gui.global::<VirtualKeyboardHandler>().on_key_pressed({
        let gui_weak = gui_weak.clone();
        move |key| {
            if let Some(gui) = gui_weak.upgrade() {
                gui.window()
                    .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: key.clone() });
                gui.window()
                    .dispatch_event(slint::platform::WindowEvent::KeyReleased { text: key });
            }
        }
    });

    gui.on_quit({
        move || {
            info!("Exiting");
            exit(0)
        }
    });

    gui.run()?;

    Ok(())
}
