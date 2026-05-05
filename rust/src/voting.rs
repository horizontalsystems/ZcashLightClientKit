//! C FFI for the voting functionality.
//!
//! Implementation is split into submodules for navigation. Exported FFI functions
//! keep their stable C symbols with `#[unsafe(no_mangle)]`.

pub mod share_tracking;
