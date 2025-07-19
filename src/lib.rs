mod drivers_license;
mod vehicle_license;

use wasm_bindgen::prelude::*;
use drivers_license::{parse_bytes as parse_drivers_bytes, DriversLicenseData};
use vehicle_license::{parse_bytes as parse_vehicle_bytes, VehicleLicenseData};

#[wasm_bindgen]
pub fn parse_drivers_license(bytes: &[u8]) -> Result<JsValue, JsValue> {
    parse_drivers_bytes(bytes.to_vec())
        .map(|data: DriversLicenseData| serde_wasm_bindgen::to_value(&data).expect("Failed to serialize to JsValue"))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn parse_vehicle_license(bytes: &[u8]) -> Result<JsValue, JsValue> {
    parse_vehicle_bytes(bytes.to_vec())
        .map(|data: VehicleLicenseData| serde_wasm_bindgen::to_value(&data).expect("Failed to serialize to JsValue"))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
