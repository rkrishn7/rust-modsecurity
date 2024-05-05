use crate::{ModSecurity, ModSecurityResult, Rules};

use modsecurity_sys::{
    msc_new_transaction, msc_process_logging, Transaction as ModSecurityTransaction,
};

type LogCallback = Box<dyn Fn(Option<&str>) + Send + Sync + 'static>;

pub struct Transaction<'a> {
    inner: *mut ModSecurityTransaction,
    ms: &'a ModSecurity,
    rules: &'a Rules,
    log_cb: Option<LogCallback>,
}

impl<'a> Transaction<'a> {
    pub fn new(ms: &'a ModSecurity, rules: &'a Rules, log_cb: Option<LogCallback>) -> Self {
        let msc_transaction = unsafe {
            msc_new_transaction(
                ms.inner(),
                rules.inner(),
                log_cb
                    .as_ref()
                    .map(|cb| &**cb as *const _ as *mut std::os::raw::c_void)
                    .unwrap_or(std::ptr::null_mut()),
            )
        };

        // SAFETY: We keep `log_cb` alive as long as the `Transaction` is alive so it's safe to
        // invoke it in the callback.
        Self {
            inner: msc_transaction,
            ms,
            rules,
            log_cb,
        }
    }

    pub fn process_logging(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { msc_process_logging(self.inner) };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessLogging)
        } else {
            Ok(())
        }
    }

    pub fn process_connection(
        &mut self,
        client: &str,
        c_port: i32,
        server: &str,
        s_port: i32,
    ) -> ModSecurityResult<()> {
        let client = std::ffi::CString::new(client).unwrap();
        let server = std::ffi::CString::new(server).unwrap();

        let result = unsafe {
            modsecurity_sys::msc_process_connection(
                self.inner,
                client.as_ptr(),
                c_port,
                server.as_ptr(),
                s_port,
            )
        };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessConnection)
        } else {
            Ok(())
        }
    }
}
