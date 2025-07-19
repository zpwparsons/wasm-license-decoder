# WASM South African License Decoder
A Rust WebAssembly (WASM) library for decoding South African driver's and vehicle license data from PDF417 barcodes.

## Overview
The decoder takes the barcode data found on South African driver’s and vehicle licenses, decrypts it, and returns the information as structured JSON. 

It supports both V1 and V2 driver's license formats, extracting key details like surname, initials, license number, date of birth, and more.

## Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) for building WebAssembly

## Installation

1. **Clone the Repository**:
```bash
git clone https://github.com/zpwparsons/wasm-license-decoder.git

cd wasm-license-decoder
```

3. Build the Project
```bash
cargo build

wasm-pack build --target web
```

4. **Usage**
```javascript
import init, { parse_drivers_license, parse_vechile_license } from './wasm/wasm_license_decoder.js';
 
await init(); // Instantiate the .wasm binary.

const driversLicense = ''; // 720 byte scan result of a PDF417 barcode.
const vehicleLicense = '';

parse_drivers_license(driversLicense);
parse_vechile_license(vehicleLicense);
```