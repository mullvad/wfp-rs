//! # Windows Filtering Platform (WFP) Rust library
//!
//! This crate provides a safe Rust library around the Windows Filtering Platform API,
//! allowing you to create and manage network filters on Windows.
//!
//! ## Overview
//!
//! The Windows Filtering Platform is a set of APIs that allow applications to handle
//! filtering and processing of network traffic.
//! This crate provides a type-safe interface to create filters that can block or permit
//! network traffic based on various criteria.
//!
//! ## Basic Usage
//!
//! ```no_run
//! use wfp::{FilterEngineBuilder, FilterBuilder, PortConditionBuilder, ActionType, Layer, Transaction};
//! use std::io;
//!
//! fn main() -> io::Result<()> {
//!     // Open a dynamic filter engine session
//!     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
//!     
//!     // Create a transaction for atomic filter operations
//!     let transaction = Transaction::new(&mut engine)?;
//!     
//!     // Create and add a filter
//!     FilterBuilder::default()
//!         .name("Block outbound connections")
//!         .description("Blocks all outbound IPv4 connections")
//!         .action(ActionType::Block)
//!         .layer(Layer::ConnectV4)
//!         .condition(
//!             PortConditionBuilder::remote()
//!                 .equal(80)
//!                 .build(),
//!         )
//!         .add(&transaction)?;
//!     
//!     // Commit the transaction
//!     transaction.commit()?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Examples
//!
//! See the `examples/` directory for more usage examples.
//!
//! Run examples with: `cargo run --example <example>`

#![cfg(target_os = "windows")]

mod action;
mod blob;
mod condition;
mod engine;
mod r#enum;
mod filter;
mod layer;
mod provider;
mod sublayer;
mod transaction;
mod util;

// Re-export public API
pub use action::ActionType;
pub use condition::*;
pub use engine::{FilterEngine, FilterEngineBuilder};
pub use r#enum::{
    EnumItem, Enumerator, Filter, FilterEnumItem, FilterEnumerator, SubLayer, SubLayerEnumItem,
    SubLayerEnumerator,
};
pub use filter::*;
pub use layer::*;
pub use provider::*;
pub use sublayer::*;
pub use transaction::Transaction;

// Re-export publicly exposed types from external crates
pub use windows_sys::core::GUID;
