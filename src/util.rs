use serde::Deserialize;

use crate::error::AppError;

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    pub fn try_i64(&self) -> Result<i64, AppError> {
        match self {
            NumberOrString::Number(value) => Ok(*value),
            NumberOrString::String(value) => value
                .parse::<i64>()
                .map_err(|_| AppError::BadRequest("Invalid number".into())),
        }
    }

    pub fn try_i32(&self) -> Result<i32, AppError> {
        match self {
            NumberOrString::Number(value) => i32::try_from(*value)
                .map_err(|_| AppError::BadRequest("Number does not fit in i32".into())),
            NumberOrString::String(value) => value
                .parse::<i32>()
                .map_err(|_| AppError::BadRequest("Invalid number".into())),
        }
    }
}
