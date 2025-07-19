use std::error::Error;
use std::fmt;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct VehicleLicenseData {
    make: String,
    description: String,
    color: String,
    license_number: String,
    vin_number: String,
    vehicle_register_number: String,
    engine_number: String,
    expiry_date: String,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidUtf8(std::string::FromUtf8Error),
    InsufficientParts,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidUtf8(err) => write!(f, "Invalid UTF-8: {}", err),
            ParseError::InsufficientParts => write!(f, "Input data does not contain enough parts"),
        }
    }
}

impl Error for ParseError {}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParseError::InvalidUtf8(err)
    }
}

impl VehicleLicenseData {
    pub fn from_parts(parts: &[&str]) -> Result<Self, ParseError> {
        if parts.len() < 16 {
            return Err(ParseError::InsufficientParts);
        }
        Ok(VehicleLicenseData {
            make: format!("{} {}", parts[9], parts[10]),
            description: parts[8].to_string(),
            color: parts[11].to_string(),
            license_number: parts[6].to_string(),
            vin_number: parts[12].to_string(),
            vehicle_register_number: parts[7].to_string(),
            engine_number: parts[13].to_string(),
            expiry_date: parts[14].to_string(),
        })
    }
}

#[allow(dead_code)]
pub fn parse_bytes(bytes: Vec<u8>) -> Result<VehicleLicenseData, ParseError> {
    let data = String::from_utf8(bytes)?;
    parse_string(data)
}

#[allow(dead_code)]
pub fn parse_string(data: String) -> Result<VehicleLicenseData, ParseError> {
    let parts: Vec<&str> = data.split('%').collect();
    VehicleLicenseData::from_parts(&parts)
}
