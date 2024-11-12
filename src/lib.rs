mod licore;
mod liclient;


pub use licore::LiCoreV1;
pub use liclient::LiClient;


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use base64::{Engine as _, prelude::*};

    // 辅助函数
    fn create_test_client() -> LiClient {
        LiClient::new(LiCoreV1 {
            act_aes_key: *b"TestKeyABC123456",
            act_aes_padding: Some("PKCS7"),
            lic_aes_key: *b"TestKeyABC123456",
            lic_aes_padding: Some("PKCS7"),
        })
    }

    // 测试 LiClient 的基本功能
    #[test]
    fn test_client_creation() {
        let client = create_test_client();
        // 测试客户端是否可以正常创建和使用
        assert!(client.gen_actoken().is_ok());
    }

    // 测试激活令牌生成
    #[test]
    fn test_actoken_generation() -> Result<()> {
        let client = create_test_client();
        let token = client.gen_actoken()?;
        
        // 验证 token 不为空
        assert!(!token.is_empty());
        // 验证 token 是有效的 base64
        assert!(BASE64_STANDARD.decode(&token).is_ok());
        
        Ok(())
    }

    // 测试许可证生成和验证
    #[test]
    fn test_license_generation_and_verification() -> Result<()> {
        let client = create_test_client();
        
        // 生成激活令牌
        let actoken = client.gen_actoken()?;
        
        // 使用激活令牌生成许可证
        let license = client.gen_license(&actoken)?;
        
        // 验证许可证
        assert!(client.verify_license(license)?);
        
        Ok(())
    }

    // 测试无效许可证
    #[test]
    fn test_invalid_license() -> Result<()> {
        let client = create_test_client();
        
        // 测试空许可证
        assert!(!client.verify_license("".to_string())?);
        
        // 测试无效的 base64
        assert!(client.verify_license("invalid-base64".to_string()).is_err());
        
        // 测试有效的 base64 但内容无效
        let invalid_license = BASE64_STANDARD.encode("invalid content");
        assert!(!client.verify_license(invalid_license)?);
        
        Ok(())
    }

    // 测试不同密钥的客户端
    #[test]
    fn test_different_keys() -> Result<()> {
        let client1 = create_test_client();
        let client2 = LiClient::new(LiCoreV1 {
            act_aes_key: *b"DiffStringKeyABC",
            act_aes_padding: Some("PKCS7"),
            lic_aes_key: *b"DiffStringKeyABC",
            lic_aes_padding: Some("PKCS7"),
        });

        // 生成许可证
        let actoken1 = client1.gen_actoken()?;
        let license1 = client1.gen_license(&actoken1)?;

        // 验证使用不同密钥的客户端无法验证许可证
        assert!(!client2.verify_license(license1)?);
        
        Ok(())
    }

    // 测试并发操作
    #[tokio::test]
    async fn test_concurrent_operations() -> Result<()> {
        use tokio::task;
        
        let client = create_test_client();
        let mut handles = vec![];

        // 创建多个并发任务
        for _ in 0..10 {
            let client = client.clone();
            let handle = task::spawn(async move {
                let actoken = client.gen_actoken()?;
                let license = client.gen_license(&actoken)?;
                client.verify_license(license)
            });
            handles.push(handle);
        }

        // 等待所有任务完成并验证结果
        for handle in handles {
            let result = handle.await??;
            assert!(result);
        }

        Ok(())
    }

    // 测试错误情况的恢复
    #[test]
    fn test_error_recovery() -> Result<()> {
        let client = create_test_client();
        
        // 测试连续操作后的错误恢复
        let mut results = vec![];
        
        for _ in 0..5 {
            // 正常操作
            let actoken = client.gen_actoken()?;
            let license = client.gen_license(&actoken)?;
            results.push(client.verify_license(license)?);
            
            // 错误操作
            let _ = client.verify_license("invalid".to_string());
            
            // 继续正常操作
            let actoken = client.gen_actoken()?;
            let license = client.gen_license(&actoken)?;
            results.push(client.verify_license(license)?);
        }
        
        // 验证所有正常操作都成功
        assert!(results.iter().all(|&r| r));
        
        Ok(())
    }
}