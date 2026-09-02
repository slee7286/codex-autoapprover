use std::sync::{
    Arc,
    atomic::AtomicBool,
};

use anyhow::{Context, Result};
use signal_hook::{
    SigId,
    consts::{SIGINT, SIGTERM},
    flag, low_level,
};

pub struct InterruptRegistration {
    pub flag: Arc<AtomicBool>,
    ids: [SigId; 2],
}

impl Drop for InterruptRegistration {
    fn drop(&mut self) {
        for id in self.ids {
            low_level::unregister(id);
        }
    }
}

pub fn register_interrupt_flag() -> Result<InterruptRegistration> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let sigint =
        flag::register(SIGINT, Arc::clone(&interrupted)).context("register Ctrl-C handler")?;
    let sigterm = match flag::register(SIGTERM, Arc::clone(&interrupted)) {
        Ok(sigterm) => sigterm,
        Err(error) => {
            low_level::unregister(sigint);
            return Err(error).context("register termination handler");
        }
    };
    Ok(InterruptRegistration {
        flag: interrupted,
        ids: [sigint, sigterm],
    })
}
