use num_bigint_dig::BigUint;
use std::error::Error;
use serde::Serialize;

#[derive(Debug)]
enum Version {
    V1,
    V2,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct DriversLicenseData {
    vehicle_codes: Vec<String>,
    surname: String,
    initials: String,
    pr_dp_code: Option<String>,
    id_country_of_issue: String,
    license_country_of_issue: String,
    vehicle_restrictions: Vec<String>,
    license_number: String,
    id_number: String,
    id_number_type: String,
    license_code_issue_dates: Vec<String>,
    driver_restriction_codes: String,
    prd_permit_expiry_date: Option<String>,
    license_issue_number: String,
    birthdate: String,
    license_issue_date: String,
    license_expiry_date: String,
    gender: String,
    image_width: u8,
    image_height: u8,
}

#[derive(Debug)]
pub enum DriversLicenseError {
    InsufficientBytes,
    UnknownVersion,
}

impl Error for DriversLicenseError {}

impl std::fmt::Display for DriversLicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriversLicenseError::InsufficientBytes => write!(f, "Invalid license (insufficient bytes)"),
            DriversLicenseError::UnknownVersion => write!(f, "Unrecognized license version"),
        }
    }
}

pub fn parse_bytes(bytes: Vec<u8>) -> Result<DriversLicenseData, Box<dyn Error>> {
    if bytes.len() != 720 {
        return Err(Box::new(DriversLicenseError::InsufficientBytes));
    }

    let version = match bytes.get(..4) {
        Some([0x01, 0xe1, 0x02, 0x45]) => Version::V1,
        Some([0x01, 0x9b, 0x09, 0x45]) => Version::V2,
        _ => return Err(Box::new(DriversLicenseError::UnknownVersion)),
    };

    let decrypted: Result<Vec<u8>, Box<dyn Error>> = match version {
        Version::V1 => decrypt_v1(&bytes[6..]),
        Version::V2 => decrypt_v2(&bytes[6..]),
    };

    parse_data(decrypted)
}

fn decrypt_v1(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let pk_128 = load_public_key("pk_v1_128")?;
    let pk_74 = load_public_key("pk_v1_74")?;
    decrypt_payload(payload, &pk_128, &pk_74)
}

fn decrypt_v2(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let pk_128 = load_public_key("pk_v2_128")?;
    let pk_74 = load_public_key("pk_v2_74")?;
    decrypt_payload(payload, &pk_128, &pk_74)
}

struct PublicKey {
    n: BigUint, // Modulus
    e: BigUint, // Exponent
}

fn load_public_key(key_name: &str) -> Result<PublicKey, Box<dyn Error>> {
    let (modulus_hex, exponent_hex) = match key_name {
        "pk_v1_128" => (
            "00fed2e1c27e3363316e77317a7a52c54981395186be4974760c72518d63e0544a48d088b332c5b0c370c765d65d983c1f9de0a42b310ccc07ae770bd2b61d6a4dcceac757689bdcbf608478faf312f6087cc496c3762cf5c4651caecda3499fae7edb7e0e3e18eb304170e91ed5b156aace6f432d6eca6cc35851de8c678f67",
            "00bb797ffdec7f9e42c9d6f79b137059db",
        ),
        "pk_v1_74" => (
            "00ff3cec6b5f40e3c3661451b9fcfaef3aeb06dc2329c0e6f4dccc9279726716ce15bbe05eed2c5711bcf8f5b6c8f7276db5c43bfaa3040dc01ab14b9c4d16f71c0ce5ea953f0c754c6b17",
            "00db05ba822d9acc33fab7d8f427f9ce65",
        ),
        "pk_v2_128" => (
            "00ca9f18ef6c3f3fa4c5a461fea54ab19406ba5ecd746d60a27492dca3d74e3b5c1d315f7b10383241809b029ebbd5de4d116030cc57f7d5a6c9a16f373bb14a508523f7e80a4c744d9085663a4a1472d7af2c56ae41b5065f7efa0293bd3278ad693546f9f16219b79ff471a3636824cffcdb63a8ed8059e6b9a4f0db895381cb",
            "187092da6454ceb1853e6915f8466a05",
        ),
        "pk_v2_74" => (
            "00b404a0df11d1cacf1a1a048d4d573f953a62c583d74925927561a6d7a1e2b14042526af70b550547390ea6ec748d30fdb81adb490e0c36a1986b404b2f5f69ef5da1b663e59509130e7",
            "309cfed9719fe2a5e20c9bb44765382b",
        ),
        _ => return Err(format!("Unknown key name {}", key_name).into()),
    };

    let n = BigUint::parse_bytes(modulus_hex.replace(":", "").as_bytes(), 16)
        .ok_or_else(|| format!("Failed to parse modulus for {}", key_name))?;
    let e = BigUint::parse_bytes(exponent_hex.replace(":", "").as_bytes(), 16)
        .ok_or_else(|| format!("Failed to parse exponent for {}", key_name))?;

    Ok(PublicKey { n, e })
}

fn decrypt_payload(payload: &[u8], pk_128: &PublicKey, pk_74: &PublicKey) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut decrypted: Vec<u8> = Vec::new();

    for chunk in payload.chunks(128).take(5) {
        let block: Vec<u8> = decrypt_block(chunk, pk_128)?;
        decrypted.extend_from_slice(&block);
    }

    let final_block: Vec<u8> = decrypt_block(&payload[5 * 128..], pk_74)?;
    decrypted.extend_from_slice(&final_block);

    Ok(decrypted)
}

fn decrypt_block(block: &[u8], key: &PublicKey) -> Result<Vec<u8>, Box<dyn Error>> {
    let input: BigUint = BigUint::from_bytes_be(block);
    let output: BigUint = input.modpow(&key.e, &key.n);
    let decrypted_bytes: Vec<u8> = output.to_bytes_be();
    Ok(decrypted_bytes)
}

fn parse_data(data: Result<Vec<u8>, Box<dyn Error>>) -> Result<DriversLicenseData, Box<dyn Error>> {
    let data = data?;
    let mut index = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte == 0x82 {
            index = i;
            break;
        }
    }

    index += 2;

    let (vehicle_codes, new_index) = read_strings(&data, index, 3)?;
    index = new_index;

    let (surname, new_index, _) = read_string(&data, index)?;
    index = new_index;

    let (initials, new_index, delimiter) = read_string(&data, index)?;
    index = new_index;

    let mut pr_dp_code = None;
    if delimiter == 0xe0 {
        let (code, new_index, _) = read_string(&data, index)?;
        index = new_index;
        pr_dp_code = Some(code);
    }

    let (id_country_of_issue, new_index, _) = read_string(&data, index)?;
    index = new_index;

    let (license_country_of_issue, new_index, _) = read_string(&data, index)?;
    index = new_index;

    let (vehicle_restrictions, new_index) = read_strings(&data, index, 3)?;
    index = new_index;

    let (license_number, new_index, _) = read_string(&data, index)?;
    index = new_index;

    let mut id_number = String::new();
    for _ in 0..13 {
        if index < data.len() {
            id_number.push(data[index] as char);
            index += 1;
        } else {
            return Err("Data ended prematurely while reading ID number".into());
        }
    }

    let id_number_type = format!("{:02}", data[index]);
    index += 1;

    let mut nibble_queue = Vec::new();
    while index < data.len() {
        let current_byte = data[index];
        index += 1;
        if current_byte == 0x57 {
            break;
        }
        nibble_queue.push(current_byte >> 4);
        nibble_queue.push(current_byte & 0x0F);
    }

    let license_code_issue_dates = read_nibble_date_list(&mut nibble_queue, 4);

    let driver_restriction_codes = format!("{}{}", nibble_queue.remove(0), nibble_queue.remove(0));

    let prd_permit_expiry_date = Some(read_nibble_date_string(&mut nibble_queue)).filter(|s| !s.is_empty());

    let license_issue_number = format!("{}{}", nibble_queue.remove(0), nibble_queue.remove(0));

    let birthdate = read_nibble_date_string(&mut nibble_queue);

    let license_issue_date = read_nibble_date_string(&mut nibble_queue);

    let license_expiry_date = read_nibble_date_string(&mut nibble_queue);

    let gender_code = format!("{}{}", nibble_queue.remove(0), nibble_queue.remove(0));

    let gender = if gender_code == "01" { "male".to_string() } else { "female".to_string() };

    index += 3;
    let image_width = data[index];
    index += 2;
    let image_height = data[index];

    Ok(DriversLicenseData {
        vehicle_codes,
        surname,
        initials,
        pr_dp_code,
        id_country_of_issue,
        license_country_of_issue,
        vehicle_restrictions,
        license_number,
        id_number,
        id_number_type,
        license_code_issue_dates,
        driver_restriction_codes,
        prd_permit_expiry_date,
        license_issue_number,
        birthdate,
        license_issue_date,
        license_expiry_date,
        gender,
        image_width,
        image_height,
    })
}

fn read_strings(data: &[u8], mut index: usize, length: usize) -> Result<(Vec<String>, usize), Box<dyn Error>> {
    let mut strings = Vec::with_capacity(length);

    for _ in 0..length {
        let mut string = String::new();
        loop {
            match data.get(index) {
                Some(&b) if b == 0xe0 || b == 0xe1 => {
                    index += 1;
                    if !string.is_empty() {
                        strings.push(string);
                    }
                    break;
                },
                Some(&b) => {
                    string.push(b as char);
                    index += 1;
                },
                None => {
                    if !string.is_empty() {
                        strings.push(string);
                    }
                    return Ok((strings, index));
                }
            }
        }
    }

    Ok((strings, index))
}

fn read_string(data: &[u8], mut index: usize) -> Result<(String, usize, u8), Box<dyn Error>> {
    let mut string = String::new();
    loop {
        match data.get(index) {
            Some(&b) if b == 0xe0 || b == 0xe1 => {
                let delimiter = b;
                index += 1;
                return Ok((string, index, delimiter));
            },
            Some(&b) => {
                string.push(b as char);
                index += 1;
            },
            None => return Err("Unexpected end of data while reading string".into()),
        }
    }
}

pub fn read_nibble_date_list(nibble_queue: &mut Vec<u8>, length: usize) -> Vec<String> {
    let mut date_list = Vec::new();

    for _ in 0..length {
        let date_string = read_nibble_date_string(nibble_queue);
        if !date_string.is_empty() {
            date_list.push(date_string);
        }
    }

    date_list
}

fn read_nibble_date_string(nibble_queue: &mut Vec<u8>) -> String {
    let m = nibble_queue.remove(0);
    if m == 10 {
        return String::new();
    }

    let c = nibble_queue.remove(0);
    let d = nibble_queue.remove(0);
    let y = nibble_queue.remove(0);

    let m1 = nibble_queue.remove(0);
    let m2 = nibble_queue.remove(0);

    let d1 = nibble_queue.remove(0);
    let d2 = nibble_queue.remove(0);

    format!("{}{}{}{}/{}{}/{}{}", m, c, d, y, m1, m2, d1, d2)
}
