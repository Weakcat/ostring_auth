use anyhow::{anyhow, Result};
// license client: 授权客户端  不需要关心token怎么生成
use super::licore::LiCoreV1;

#[derive(Clone, Default, serde::Serialize, Debug)]
pub struct LiClient {
    license_core: LiCoreV1,
    // actokey:String,
}

impl LiClient {
    pub fn new(lic_core: LiCoreV1) -> LiClient {
        LiClient { license_core: lic_core }
    }

    // 生产激活token--带有时间信息
    pub fn gen_actoken(&self) -> Result<String> {
        self.license_core.gen_actoken()
    }

    pub fn gen_license(&self, active_str: &str) -> Result<String> {
        let actokey = &active_str[0..4];
        let actoken = &active_str[4..];
        let (key, token_uuid) = self.license_core.gen_actokey(&actoken);
        println!("actokey:{}", key);
        if actokey == key {
            let license = self.license_core.generate_lic(token_uuid)?;
            println!("license:{}", license);
            return Ok(license);
        }

        return Err(anyhow!("actokey not match"));
    }

    pub fn verify_license(&self, license_content: String) -> Result<bool> {
        self.license_core.verify_lic(license_content)
    }
}
