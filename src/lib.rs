#![deny(unknown_lints)]
#![deny(renamed_and_removed_lints)]
#![forbid(unsafe_code)]
#![deny(deprecated)]
#![forbid(private_interfaces)]
#![forbid(private_bounds)]
#![forbid(non_fmt_panics)]
#![deny(unreachable_code)]
#![deny(unreachable_patterns)]
#![forbid(unused_doc_comments)]
#![forbid(unused_must_use)]
#![deny(while_true)]
#![deny(unused_parens)]
#![deny(redundant_semicolons)]
#![deny(non_ascii_idents)]
#![deny(confusable_idents)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::cargo_common_metadata)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]
#![deny(clippy::mod_module_files)]
#![doc = include_str!("../README.md")]

pub mod basic;
pub mod conversion;
pub mod filter;
pub mod schema;
