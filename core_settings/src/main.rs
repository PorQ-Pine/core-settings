use std::{
    process::exit,
    rc::Rc,
    sync::{
        Arc, Mutex,
        mpsc::{Receiver, Sender, channel},
    },
};

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
    let (original_boot_config, _) = BootConfig::read()?;
    info!("Original boot configuration: {:?}", &original_boot_config);
    let boot_config = Arc::new(Mutex::new(original_boot_config.clone()));

    // GUI
    let gui = CoreSettings::new().with_context(|| "Failed to initialize Slint UI")?;
    let gui_weak = gui.as_weak();
    let (quit_sender, quit_receiver): (Sender<()>, Receiver<()>) = channel();

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
    {
        let locked_boot_config = boot_config.lock().unwrap().clone();
        if !locked_boot_config.flags.first_boot_done {
            gui.set_page(Page::OOBE);
        } else {
            gui.set_page(Page::SettingsMenu);
        }
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

    let create_user_timer = Rc::new(Timer::default());
    gui.on_create_user({
        let quit_sender = quit_sender.clone();
        let boot_config = boot_config.clone();
        let gui_weak = gui_weak.clone();
        move |username, password, admin, quit_afterwards, make_default| {
            let boot_config_to_provide;
            if make_default {
                boot_config_to_provide = Some(boot_config.clone());
            } else {
                boot_config_to_provide = None;
            }

            gui_fn::users::create(
                gui_weak.clone(),
                username,
                password,
                admin,
                make_default,
                &create_user_timer,
                quit_sender.clone(),
                quit_afterwards,
                boot_config_to_provide,
            );
        }
    });

    let quit_timer = Rc::new(Timer::default());
    quit_timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_millis(100),
        {
            let gui_weak = gui_weak.clone();
            move || {
                if let Ok(()) = quit_receiver.try_recv() {
                    if let Err(e) = quit(&original_boot_config, boot_config.clone()) {
                        if let Some(gui) = gui_weak.upgrade() {
                            gui_fn::error_toast(&gui, "Failed to quit", e.into());
                        }
                    }
                }
            }
        },
    );

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
        let quit_sender = quit_sender.clone();
        move || {
            let _ = quit_sender.send(());
        }
    });

    gui.run()?;

    Ok(())
}

fn quit(original_boot_config: &BootConfig, boot_config: Arc<Mutex<BootConfig>>) -> Result<()> {
    info!("Exiting");

    let mut final_boot_config = boot_config.lock().unwrap().clone();
    final_boot_config.flags.first_boot_done = true;
    if final_boot_config != *original_boot_config {
        BootConfig::write(&final_boot_config, false)?;
    } else {
        info!("Boot configuration did not change: not writing it back");
    }

    exit(0);
}
