use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use windows_sys::Win32::Foundation::{BOOL, FALSE, TRUE};
use windows_sys::Win32::System::Console::{CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler};

static INTERRUPT_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

pub struct InterruptRegistration {
    pub flag: Arc<AtomicBool>,
}

impl Drop for InterruptRegistration {
    fn drop(&mut self) {
        if let Some(flag) = INTERRUPT_FLAG.get() {
            flag.store(false, Ordering::Release);
        }
        unsafe {
            SetConsoleCtrlHandler(Some(console_ctrl_handler), FALSE);
        }
    }
}

pub fn register_interrupt_flag() -> Result<InterruptRegistration> {
    let flag = INTERRUPT_FLAG
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    flag.store(false, Ordering::Release);
    let ok = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), TRUE) };
    if ok == FALSE {
        anyhow::bail!("register console interrupt handler");
    }
    Ok(InterruptRegistration { flag })
}

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT {
        if let Some(flag) = INTERRUPT_FLAG.get() {
            flag.store(true, Ordering::Release);
        }
        return TRUE;
    }
    FALSE
}
