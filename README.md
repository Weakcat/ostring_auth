# OStringAuth

OStringAuth 是一个基于 AES 对称加密算法的许可证认证模块，提供了安全可靠的软件授权解决方案。

## 功能特点

- 基于 AES 对称加密算法
- 支持自定义加密密钥
- 支持 PKCS7 填充模式
- 提供许可证生成和验证功能
- 支持并发操作
- 内置错误恢复机制

## 使用方法

### 1. 创建客户端
```rust
let client = LiClient::new(LiCoreV1 {
act_aes_key: b"YourAESKey123456", // 16字节的AES密钥
act_aes_padding: Some("PKCS7"), // 填充模式
lic_aes_key: b"YourAESKey123456", // 许可证加密密钥
lic_aes_padding: Some("PKCS7"), // 许可证填充模式
});
```

### 2. 生成激活码
```rust
// 生成激活令牌
let actoken = client.gen_actoken()?;
// 获取激活码
let (key, _) = client.license_core.gen_actokey(&actoken)?;
let activation_code = format!("{}{}", key, actoken);
```

### 3. 生成许可证
```rust
let license = client.gen_license(&activation_code)?;
```

### 4. 验证许可证
```rust
let is_valid = client.verify_license(license)?;
```


## 安全性

- 使用 AES 加密算法保护许可证内容
- 支持自定义加密密钥和填充模式
- 内置防篡改机制

## 错误处理

模块提供了完善的错误处理机制：
- 无效的激活码处理
- 许可证验证失败处理
- 加密/解密错误处理
