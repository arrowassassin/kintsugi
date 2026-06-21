//! Tauri `invoke` binding for the Dioxus/WASM frontend.
//!
//! Calls `window.__TAURI__.core.invoke` (the Tauri host enables it via
//! `app.withGlobalTauri = true`). Arguments are serialized from a Rust `Serialize`
//! value and the reply is deserialized into the shared view-model type — so a
//! command's parameter and return shapes are checked against the engine at compile
//! time on this side too.

use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

/// Invoke a Tauri command, returning its deserialized reply. `args` is serialized
/// to a JS object whose fields Tauri matches to the command's parameters; pass
/// `()` for a command that takes none.
pub async fn invoke<T, A>(cmd: &str, args: A) -> Result<T, String>
where
    T: DeserializeOwned,
    A: Serialize,
{
    let args = serde_wasm_bindgen::to_value(&args).map_err(|e| e.to_string())?;
    let reply = tauri_invoke(cmd, args)
        .await
        .map_err(|e| format!("invoke {cmd} failed: {e:?}"))?;
    serde_wasm_bindgen::from_value(reply).map_err(|e| e.to_string())
}
