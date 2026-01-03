# 🔐 Secure Message Protocol v2.0

[English](#english) | [中文](#中文)

---

## English

A cyberpunk-style secure message encryption/decryption demo using real Web Crypto API.

### Features

- **ECDH Key Exchange** - P-256 curve Diffie-Hellman for secure key agreement
- **ECDSA Digital Signature** - Message authentication and integrity verification
- **AES-256-GCM Encryption** - Authenticated symmetric encryption
- **SHA-256/SHA-512 Hashing** - Cryptographic hash functions
- **Matrix Rain Background** - Animated cyberpunk aesthetic

### How to Use

1. Open `index.html` in a modern browser
2. Choose **ENCRYPT** or **DECRYPT** mode

**Encryption:**
- Enter sender ID, recipient ID, and message
- Click "INITIATE ENCRYPTION PROTOCOL"
- Copy the encrypted payload and key
- Send payload to recipient, share key via secure channel

**Decryption:**
- Paste encrypted payload and decryption key
- Click "INITIATE DECRYPTION PROTOCOL"
- View the decrypted message with signature verification

### Tech Stack

- Vanilla JavaScript with Web Crypto API
- Pure CSS with neon terminal styling
- No external dependencies

### File Structure

```
├── index.html    # Main HTML structure
├── style.css     # Terminal-style CSS
├── crypto.js     # Cryptographic utilities
└── app.js        # Application logic
```

---

## 中文

一个赛博朋克风格的安全消息加密/解密演示，使用真实的 Web Crypto API 实现。

### 功能特性

- **ECDH 密钥交换** - P-256 曲线 Diffie-Hellman 安全密钥协商
- **ECDSA 数字签名** - 消息认证和完整性验证
- **AES-256-GCM 加密** - 认证对称加密
- **SHA-256/SHA-512 哈希** - 密码学哈希函数
- **Matrix 数字雨背景** - 动态赛博朋克视觉效果

### 使用方法

1. 在现代浏览器中打开 `index.html`
2. 选择 **加密** 或 **解密** 模式

**加密流程：**
- 输入发送方 ID、接收方 ID 和消息内容
- 点击「启动加密协议」
- 复制加密数据包和密钥
- 将数据包发送给接收方，通过安全渠道分享密钥

**解密流程：**
- 粘贴加密数据包和解密密钥
- 点击「启动解密协议」
- 查看解密后的消息及签名验证结果

### 技术栈

- 原生 JavaScript + Web Crypto API
- 纯 CSS 霓虹终端风格
- 无外部依赖

### 文件结构

```
├── index.html    # 页面结构
├── style.css     # 终端风格样式
├── crypto.js     # 密码学工具类
└── app.js        # 应用逻辑
```

---

## License

MIT
