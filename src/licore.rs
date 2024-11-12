use anyhow::{anyhow, Result};
use base64::{self, engine::general_purpose, Engine};
use chrono;
use crc;
use serde::{Deserialize, Serialize};
use soft_aes::aes::{aes_dec_ecb, aes_enc_ecb};
use uuid::Uuid;
use wmi::{COMLibrary, WMIConnection, Variant};
use std::collections::HashMap;

const LICORE_VERSION: &str = "LiCoreV1.0.0";

#[derive(Serialize, Deserialize)]
struct TokenV1 {
    ver: String,
    uuid: String,
    token: String,
    sys_info: Vec<String>,
}

#[derive(Clone, Default, serde::Serialize, Debug)]
pub struct LiCoreV1 {
    pub act_aes_key: [u8; 16],
    pub act_aes_padding: Option<&'static str>,
    pub lic_aes_key: [u8; 16],
    pub lic_aes_padding: Option<&'static str>,
}

impl LiCoreV1 {
    pub fn gen_smblos_uuid(&self) -> String {
        // 还要有一个字段是判断是center还是client
        return Uuid::new_v4().to_string(); // 使用Uuid的new_v4方法
    }

    #[cfg(target_os = "windows")]
    pub fn get_smbios_uuid(&self) -> Result<String> {
        // 命令行获取bios的uuid  [wmic csproduct get UUID]
        // 我们采用wmi库来获取，不用创建新进程
        let com_con = COMLibrary::new()?;
        let wmi_con = WMIConnection::new(com_con)?;
        let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT UUID FROM Win32_ComputerSystemProduct")?;
        
        if let Some(result) = results.first() {
            if let Some(Variant::String(uuid)) = result.get("UUID") {
                return Ok(uuid.to_lowercase().clone());
            }
        }
        return Err(anyhow!("UUID not found"));
    }

    // 生成激活token--带有时间信息
    pub fn gen_actoken(&self) -> Result<String> {
        let local_time = chrono::Local::now().timestamp();
        let uuid = self.gen_smblos_uuid();
        let smblos_uuid = self.get_smbios_uuid()?;
        let token_str = format!("{};{};{};", smblos_uuid, uuid, local_time);
        let encrypted: Vec<u8> = aes_enc_ecb(
            token_str.as_bytes(),
            &self.act_aes_key,
            self.act_aes_padding,
        )
        .expect("Actoken Encryption failed");
        let token = general_purpose::STANDARD.encode(&encrypted);
        let token_pack = TokenV1 {
            ver: LICORE_VERSION.to_string(),
            uuid,
            token,
            sys_info: vec![],
        };
        let payload = serde_json::to_string(&token_pack)?;
        let encode_payload = general_purpose::STANDARD.encode(payload.as_bytes());
        Ok(encode_payload)
    }

    pub fn gen_actokey(&self, raw_token: &str) -> Result<(String, String)> {
        let decode_payload = general_purpose::STANDARD.decode(&raw_token)?;
        let json_payload = String::from_utf8(decode_payload)?;
        let actoken: TokenV1 = serde_json::from_str(&json_payload)?;
        let decode_token = general_purpose::STANDARD.decode(&actoken.token)?;
        let decode_token = aes_dec_ecb(&decode_token, &self.act_aes_key, self.act_aes_padding)
            .expect("Actokey Decryption failed");
        let token_str = String::from_utf8(decode_token)?;
        const X25: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);
        let actokey = format!("{:04X}", X25.checksum(&token_str.as_bytes()));
        Ok((format!("{actokey}"), actoken.uuid))
    }

    pub fn generate_lic(&self, uuid: String) -> Result<String> {
        let local_time = chrono::Local::now().timestamp();
        let smblos_uuid = self.get_smbios_uuid()?;
        let license_str = format!("{};{};{};", local_time, uuid, smblos_uuid);
        let encrypted: Vec<u8> = aes_enc_ecb(
            license_str.as_bytes(),
            &self.lic_aes_key,
            self.lic_aes_padding,
        )
        .expect("License Encryption failed");
        let token = general_purpose::STANDARD.encode(&encrypted);
        let token_pack = TokenV1 {
            ver: LICORE_VERSION.to_string(),
            uuid,
            token,
            sys_info: vec![],
        };
        let payload = serde_json::to_string(&token_pack)?;
        let encode_payload = general_purpose::STANDARD.encode(&payload);
        Ok(format!("{encode_payload}"))
    }

    pub fn verify_lic(&self, lic_str: String) -> Result<bool> {
        let decode_payload = general_purpose::STANDARD.decode(&lic_str)?;
        let json_payload = String::from_utf8(decode_payload)?;
        let lic_token: TokenV1 = serde_json::from_str(&json_payload)?;
        let smblos_uuid: String = lic_token.uuid;
        let decode_token = general_purpose::STANDARD.decode(&lic_token.token)?;
        let decode_token = aes_dec_ecb(&decode_token, &self.lic_aes_key, self.lic_aes_padding).map_err(|_| anyhow!("License Decryption failed"))?;
        let token_str = String::from_utf8(decode_token)?;
        let smbios_uuid = self.get_smbios_uuid()?;
        let compare_str = format!("{};{};", smblos_uuid, smbios_uuid);
        let compare_result = token_str.contains(&compare_str);
        Ok(compare_result)
    }
}
