use modsecurity_sys::{ModSecLogCb, ModSecurity, ModSecurityIntervention, RulesSet, Transaction};

pub(crate) mod types {
    pub use modsecurity_sys::{ModSecurityIntervention_t, ModSecurity_t, Rules_t, Transaction_t};
}

macro_rules! sys_passthrough {
    // With return type
    ($(
        unsafe fn $name:ident(
            $($param_name:ident: $param_type:ty),*
        ) $( -> $ret:ty)?;
    )*) => {
        $(
            unsafe fn $name($($param_name: $param_type),*) $( -> $ret)? {
                ::modsecurity_sys::$name($($param_name),*)
            }
        )*
    };
}

/// A trait that wraps the FFI bindings to ModSecurity.
/// Consumers of this library should not need to use this trait directly.
/// It is primarily used for testing.
#[allow(non_snake_case)]
#[doc(hidden)]
pub trait RawBindings {
    sys_passthrough! {
        unsafe fn msc_new_transaction(
            ms: *mut ModSecurity,
            rules: *mut RulesSet,
            logCbData: *mut ::std::os::raw::c_void
        ) -> *mut Transaction;

        unsafe fn msc_new_transaction_with_id(
            ms: *mut ModSecurity,
            rules: *mut RulesSet,
            id: *mut ::std::os::raw::c_char,
            logCbData: *mut ::std::os::raw::c_void
        ) -> *mut Transaction;

        unsafe fn msc_process_connection(
            transaction: *mut Transaction,
            client: *const ::std::os::raw::c_char,
            cPort: ::std::os::raw::c_int,
            server: *const ::std::os::raw::c_char,
            sPort: ::std::os::raw::c_int
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_request_headers(transaction: *mut Transaction) -> ::std::os::raw::c_int;

        unsafe fn msc_add_request_header(
            transaction: *mut Transaction,
            key: *const ::std::os::raw::c_uchar,
            value: *const ::std::os::raw::c_uchar
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_request_body(transaction: *mut Transaction) -> ::std::os::raw::c_int;

        unsafe fn msc_append_request_body(
            transaction: *mut Transaction,
            body: *const ::std::os::raw::c_uchar,
            size: usize
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_response_headers(
            transaction: *mut Transaction,
            code: ::std::os::raw::c_int,
            protocol: *const ::std::os::raw::c_char
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_add_response_header(
            transaction: *mut Transaction,
            key: *const ::std::os::raw::c_uchar,
            value: *const ::std::os::raw::c_uchar
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_response_body(transaction: *mut Transaction) -> ::std::os::raw::c_int;

        unsafe fn msc_append_response_body(
            transaction: *mut Transaction,
            body: *const ::std::os::raw::c_uchar,
            size: usize
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_uri(
            transaction: *mut Transaction,
            uri: *const ::std::os::raw::c_char,
            protocol: *const ::std::os::raw::c_char,
            http_version: *const ::std::os::raw::c_char
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_get_response_body_length(transaction: *mut Transaction) -> usize;

        unsafe fn msc_get_request_body_length(transaction: *mut Transaction) -> usize;

        unsafe fn msc_transaction_cleanup(transaction: *mut Transaction);

        unsafe fn msc_intervention(
            transaction: *mut Transaction,
            it: *mut ModSecurityIntervention
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_process_logging(transaction: *mut Transaction) -> ::std::os::raw::c_int;

        unsafe fn msc_init() -> *mut ModSecurity;

        unsafe fn msc_who_am_i(msc: *mut ModSecurity) -> *const ::std::os::raw::c_char;

        unsafe fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const ::std::os::raw::c_char);

        unsafe fn msc_set_log_cb(msc: *mut ModSecurity, cb: ModSecLogCb);

        unsafe fn msc_cleanup(msc: *mut ModSecurity);

        unsafe fn msc_create_rules_set() -> *mut RulesSet;

        unsafe fn msc_rules_dump(rules: *mut RulesSet);

        unsafe fn msc_rules_add_file(
            rules: *mut RulesSet,
            file: *const ::std::os::raw::c_char,
            error: *mut *const ::std::os::raw::c_char
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_rules_add(
            rules: *mut RulesSet,
            plain_rules: *const ::std::os::raw::c_char,
            error: *mut *const ::std::os::raw::c_char
        ) -> ::std::os::raw::c_int;

        unsafe fn msc_rules_cleanup(rules: *mut RulesSet) -> ::std::os::raw::c_int;
    }
}

#[derive(Clone, Copy)]
pub struct Bindings;

impl Default for Bindings {
    fn default() -> Self {
        Self
    }
}

impl RawBindings for Bindings {}
