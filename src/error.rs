use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, OperationContractError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonCode {
    ContractRejected,
    HelperRejected,
    ResultUnknown,
    Timeout,
    Unavailable,
}

impl ReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractRejected => "windows-operation-contract-rejected",
            Self::HelperRejected => "windows-operation-helper-rejected",
            Self::ResultUnknown => "windows-operation-result-unknown",
            Self::Timeout => "windows-operation-timeout",
            Self::Unavailable => "windows-operation-unavailable",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OperationContractError(pub ReasonCode);
impl Display for OperationContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}
impl std::error::Error for OperationContractError {}
impl From<ReasonCode> for OperationContractError {
    fn from(value: ReasonCode) -> Self {
        Self(value)
    }
}
