use anyhow::{Context, Result};
use log::info;
use slint::{Timer, TimerMode};
slint::include_modules!();

mod gui_fn;

fn main() -> Result<()> {
    env_logger::init();
    info!("Core Settings initializing");

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

    gui.run()?;

    Ok(())
}
