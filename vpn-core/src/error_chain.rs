//! Formattazione catena `.source()` quando il `Display` del livello più esterno è povero di dettaglio
//! (es. `libloading` su Windows stampa solo "LoadLibraryExW failed" senza codice/descrizione OS).

/// Concatena `Display` dell’errore con quello di tutte le sorgenti [`std::error::Error::source`].
pub fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    while let Some(s) = next {
        use std::fmt::Write as _;
        let _ = write!(&mut out, ": {}", s);
        next = s.source();
    }
    out
}
