//! Distribution-update building blocks.
//!
//! Local-only manifest, selection, state and outcome primitives. The
//! authenticated-manifest type has no production constructor until publisher
//! authentication exists. No network fetch, installation, activation or
//! approval decision consumes these primitives.

// The schema does not feed production admission or authorization.
#[allow(dead_code)]
pub(crate) mod manifest;

// No production constructor; synthetic byte-binding exists in tests only.
#[allow(dead_code)]
pub(crate) mod verify;

// State storage and check coordination are local-only primitives. They do not
// perform network checks, TUF verification, installation, prompting, or hook
// authorization.
#[allow(dead_code)]
pub(crate) mod state;

// Session outcomes are fixed-category local observations. They are not
// compatibility registry entries and cannot arm or authorize a hook.
pub(crate) mod outcome;

// Selection is pure and not called by the launcher.
#[allow(dead_code)]
pub(crate) mod selection;
