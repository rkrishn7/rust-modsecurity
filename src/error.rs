#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ModSecurityError {
    /// Error when converting a string to a C string
    Nul(std::ffi::NulError),
    /// Error when processing a connection
    ProcessConnection,
    /// Error when processing logging
    ProcessLogging,
    /// Error when adding a file to the rule set
    RulesAddFile(String),
}

impl From<std::ffi::NulError> for ModSecurityError {
    fn from(err: std::ffi::NulError) -> Self {
        ModSecurityError::Nul(err)
    }
}
