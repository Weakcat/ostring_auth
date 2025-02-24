use anyhow::{anyhow, Result};
// license client: 授权客户端  不需要关心token怎么生成
use super::licore::LiCoreV1;

#[derive(Clone, Default, serde::Serialize, Debug)]
pub struct LiClient {
    pub license_core: LiCoreV1,
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

    pub fn check_actokey(&self, actoken: &str, actokey: &str) -> Result<bool> {
        let (key, _) = self.license_core.gen_actokey(&actoken)?;
        return Ok(key == actokey);
    }

    pub fn gen_license(&self, actoken: &str, actokey: &str) -> Result<String> {
        let (key, token_uuid) = self.license_core.gen_actokey(&actoken)?;
        if actokey == key {
            let license = self.license_core.generate_lic(token_uuid)?;
            return Ok(license);
        }

        return Err(anyhow!("actokey not match"));
    }

    pub fn verify_license(&self, license_content: String) -> Result<bool> {
        self.license_core.verify_lic(license_content)
    }
}
