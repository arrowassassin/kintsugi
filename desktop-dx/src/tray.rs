//! System-tray status indicator: macOS menubar, Windows taskbar, Linux indicator.
//!
//! Shows the brand mark when Kintsugi is running, with a "Show Kintsugi" /
//! "Quit" menu and a left-click bringing the main window back to the front.
//! Optional — if the tray library fails to initialize (e.g. an embedded Linux
//! without AppIndicator), the app continues to work without a tray.

use std::sync::atomic::{AtomicBool, Ordering};

use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    TrayIcon, TrayIconBuilder, TrayIconEvent,
};

/// Cross-process flag the Dioxus side polls each tick — true when the tray was
/// clicked (or "Show Kintsugi" was picked from the menu) and the main window
/// should be brought to the front. Reset to false after the UI handles it.
pub static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Decode the embedded 32-px PNG into the RGBA buffer the tray library wants.
fn icon_image() -> Option<tray_icon::Icon> {
    let png = crate::ICON_PNG_32;
    let img = image::load_from_memory(png).ok()?.to_rgba8();
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).ok()
}

/// Build and install the tray. Returns the live handle (caller must keep it
/// alive). `None` on failure — we never want the app to crash because a tray
/// couldn't be created.
pub fn install_tray() -> Option<TrayIcon> {
    let menu = Menu::new();
    let item_show = MenuItem::new("Show Kintsugi", true, None);
    let item_quit = MenuItem::new("Quit", true, None);
    menu.append(&item_show).ok()?;
    menu.append(&item_quit).ok()?;
    let show_id = item_show.id().clone();
    let quit_id = item_quit.id().clone();

    let icon = icon_image();
    let mut builder = TrayIconBuilder::new()
        .with_tooltip("Kintsugi — guardrails for your AI agents (running)")
        .with_menu(Box::new(menu));
    if let Some(ico) = icon {
        builder = builder.with_icon(ico);
    }
    let tray = builder.build().ok()?;

    // Background thread that bridges tray + menu events into the SHOW_REQUESTED
    // flag (and quit). The receivers are global crossbeam channels — polling
    // them on a dedicated thread keeps the integration runtime-agnostic.
    std::thread::Builder::new()
        .name("kintsugi-tray".into())
        .spawn(move || {
            let tray_rx = TrayIconEvent::receiver();
            let menu_rx = MenuEvent::receiver();
            loop {
                if let Ok(ev) = tray_rx.recv_timeout(std::time::Duration::from_millis(250)) {
                    if matches!(
                        ev,
                        TrayIconEvent::Click {
                            button: tray_icon::MouseButton::Left,
                            button_state: tray_icon::MouseButtonState::Up,
                            ..
                        }
                    ) {
                        SHOW_REQUESTED.store(true, Ordering::SeqCst);
                    }
                }
                while let Ok(ev) = menu_rx.try_recv() {
                    if ev.id == show_id {
                        SHOW_REQUESTED.store(true, Ordering::SeqCst);
                    } else if ev.id == quit_id {
                        std::process::exit(0);
                    }
                }
            }
        })
        .ok();

    Some(tray)
}
