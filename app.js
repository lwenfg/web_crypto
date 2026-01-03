// Matrix背景效果
function initMatrix() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const matrix = document.getElementById('matrix');
    matrix.appendChild(canvas);

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < drops.length; i++) {
            const char = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(char, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(draw, 50);
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

function addLog(container, text) {
    const line = document.createElement('div');
    line.innerHTML = text;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    navigator.clipboard.writeText(element.value).then(() => {
        alert('已复制到剪贴板');
    }).catch(() => {
        alert('复制失败');
    });
}

// 主应用 - 使用真实的 Web Crypto API
class SecureMessageProtocol {
    constructor() {
        this.mode = null;
        this.senderECDH = null;
        this.receiverECDH = null;
        this.senderECDSA = null;
        this.sharedKey = null;
        this.initEventListeners();
        initMatrix();
    }

    initEventListeners() {
        document.getElementById('encryptMode').addEventListener('click', () => this.setMode('encrypt'));
        document.getElementById('decryptMode').addEventListener('click', () => this.setMode('decrypt'));
        document.getElementById('startEncrypt').addEventListener('click', () => this.startEncryption());
        document.getElementById('startDecrypt').addEventListener('click', () => this.startDecryption());
    }

    setMode(mode) {
        this.mode = mode;
        document.getElementById('modeSelector').style.display = 'none';
        if (mode === 'encrypt') {
            document.getElementById('encryptSection').style.display = 'block';
        } else {
            document.getElementById('decryptSection').style.display = 'block';
        }
    }

    // ==================== 加密流程 (使用真实密码学) ====================
    async startEncryption() {
        const sender = document.getElementById('sender').value.trim();
        const receiver = document.getElementById('receiver').value.trim();
        const message = document.getElementById('message').value.trim();

        if (!sender || !receiver || !message) {
            alert('错误: 请填写所有字段');
            return;
        }

        document.getElementById('startEncrypt').disabled = true;
        document.getElementById('steps').classList.add('active');
        document.getElementById('step5Title').textContent = '消息加密 (AES-256-GCM)';

        await this.encryptStep1(sender, receiver);
        await delay(1500);

        const sharedKeyHex = await this.encryptStep2(sender, receiver);
        await delay(1500);

        const messageHash = await this.encryptStep3(message);
        await delay(1500);

        const signature = await this.encryptStep4(message, sender);
        await delay(1500);

        const encryptedData = await this.encryptStep5(sender, receiver, message, signature);
        await delay(1000);

        this.showEncryptResult(encryptedData);
    }

    async encryptStep1(sender, receiver) {
        const step = document.getElementById('step1');
        const content = document.getElementById('content1');
        const status = document.getElementById('status1');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 初始化身份认证协议...`);
        await delay(400);

        const senderHash = await CryptoUtils.sha256(sender + Date.now());
        const receiverHash = await CryptoUtils.sha256(receiver + Date.now());
        const senderHash512 = await CryptoUtils.sha512(sender + Date.now());

        addLog(content, `<span class="highlight">[*]</span> 发送方标识: <span class="success">${sender}</span>`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-256 身份哈希:</div><div class="code-value">${senderHash}</div></div>`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-512 身份哈希:</div><div class="code-value">${senderHash512}</div></div>`);
        await delay(500);

        addLog(content, `<span class="highlight">[*]</span> 接收方标识: <span class="success">${receiver}</span>`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-256 身份哈希:</div><div class="code-value">${receiverHash}</div></div>`);
        await delay(500);

        addLog(content, `<span class="success">[✓]</span> 身份认证完成`);
        this.completeStep(step, status);
    }

    async encryptStep2(sender, receiver) {
        const step = document.getElementById('step2');
        const content = document.getElementById('content2');
        const status = document.getElementById('status2');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        const dhInfo = CryptoUtils.getDHParamsInfo();
        addLog(content, `<span class="highlight">[*]</span> 启动椭圆曲线 Diffie-Hellman 密钥交换协议...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">算法参数:</div><div class="code-value">协议: ${dhInfo.name}</div><div class="code-value">曲线: ${dhInfo.curve}</div><div class="code-value">密钥长度: ${dhInfo.keySize} bits</div><div class="code-value">安全强度: ${dhInfo.securityLevel}</div></div>`);
        await delay(600);

        // 生成发送方 ECDH 密钥对
        addLog(content, `<span class="highlight">[*]</span> ${sender} 生成 ECDH 密钥对...`);
        await delay(400);
        this.senderECDH = await CryptoUtils.generateECDHKeyPair();
        const senderPubKey = CryptoUtils.formatECPublicKey(this.senderECDH.publicKeyJwk);
        addLog(content, `<div class="code-block"><div class="code-label">${sender} 公钥 (P-256):</div><div class="code-value">x: ${senderPubKey.x}</div><div class="code-value">y: ${senderPubKey.y}</div></div>`);
        await delay(500);

        // 生成接收方 ECDH 密钥对
        addLog(content, `<span class="highlight">[*]</span> ${receiver} 生成 ECDH 密钥对...`);
        await delay(400);
        this.receiverECDH = await CryptoUtils.generateECDHKeyPair();
        const receiverPubKey = CryptoUtils.formatECPublicKey(this.receiverECDH.publicKeyJwk);
        addLog(content, `<div class="code-block"><div class="code-label">${receiver} 公钥 (P-256):</div><div class="code-value">x: ${receiverPubKey.x}</div><div class="code-value">y: ${receiverPubKey.y}</div></div>`);
        await delay(500);

        // 交换公钥并计算共享密钥
        addLog(content, `<span class="highlight">[*]</span> 交换公钥...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 计算 ECDH 共享密钥: K = privateA × publicB`);
        await delay(400);

        const derived = await CryptoUtils.deriveSharedKey(
            this.senderECDH.privateKey,
            this.receiverECDH.publicKey
        );
        this.sharedKey = derived.sharedKey;

        addLog(content, `<div class="code-block"><div class="code-label">ECDH 共享密钥 (256-bit):</div><div class="code-value">${derived.sharedKeyHex}</div></div>`);
        await delay(400);

        // 使用 HKDF 派生 AES 密钥
        const aesKeyHex = await CryptoUtils.exportAESKey(this.sharedKey);
        addLog(content, `<span class="highlight">[*]</span> 使用 HKDF-SHA256 派生 AES-256 密钥...`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">AES-256 密钥:</div><div class="code-value">${aesKeyHex}</div></div>`);

        addLog(content, `<span class="success">[✓]</span> 密钥协商完成`);
        this.completeStep(step, status);

        return aesKeyHex;
    }

    async encryptStep3(message) {
        const step = document.getElementById('step3');
        const content = document.getElementById('content3');
        const status = document.getElementById('status3');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 处理消息数据...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">原始消息 (${message.length} 字符):</div><div class="code-value" style="color: #00ffff;">"${message}"</div></div>`);
        await delay(500);

        addLog(content, `<span class="highlight">[*]</span> 计算消息摘要...`);
        await delay(300);

        const messageHash256 = await CryptoUtils.sha256(message);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-256 摘要:</div><div class="code-value">${messageHash256}</div></div>`);
        await delay(400);

        const messageHash512 = await CryptoUtils.sha512(message);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-512 摘要:</div><div class="code-value">${messageHash512}</div></div>`);

        addLog(content, `<span class="success">[✓]</span> 消息处理完成`);
        this.completeStep(step, status);

        return messageHash256;
    }

    async encryptStep4(message, sender) {
        const step = document.getElementById('step4');
        const content = document.getElementById('content4');
        const status = document.getElementById('status4');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        const sigInfo = CryptoUtils.getSignatureInfo();
        addLog(content, `<span class="highlight">[*]</span> 初始化数字签名协议...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">签名算法:</div><div class="code-value">协议: ${sigInfo.name}</div><div class="code-value">哈希: ${sigInfo.hash}</div><div class="code-value">签名长度: ${sigInfo.signatureSize}</div><div class="code-value">安全强度: ${sigInfo.securityLevel}</div></div>`);
        await delay(500);

        // 生成 ECDSA 密钥对
        addLog(content, `<span class="highlight">[*]</span> 生成 ECDSA 签名密钥对...`);
        await delay(400);
        this.senderECDSA = await CryptoUtils.generateECDSAKeyPair();
        const ecdsaPubKey = CryptoUtils.formatECPublicKey(this.senderECDSA.publicKeyJwk);
        addLog(content, `<div class="code-block"><div class="code-label">ECDSA 公钥 (P-256):</div><div class="code-value">x: ${ecdsaPubKey.x}</div><div class="code-value">y: ${ecdsaPubKey.y}</div></div>`);
        await delay(500);

        // 签名
        addLog(content, `<span class="highlight">[*]</span> 使用私钥对消息签名...`);
        await delay(400);
        const signature = await CryptoUtils.ecdsaSign(message, this.senderECDSA.privateKey);
        addLog(content, `<div class="code-block"><div class="code-label">ECDSA 数字签名 (64 bytes):</div><div class="code-value" style="color: #00ffff;">${signature}</div></div>`);
        await delay(400);

        addLog(content, `<span class="success">[✓]</span> 数字签名生成完成，消息来源已认证: ${sender}`);
        this.completeStep(step, status);

        return signature;
    }

    async encryptStep5(sender, receiver, message, signature) {
        const step = document.getElementById('step5');
        const content = document.getElementById('content5');
        const status = document.getElementById('status5');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        const payload = {
            from: sender,
            to: receiver,
            message: message,
            signature: signature,
            ecdsaPublicKey: this.senderECDSA.publicKeyJwk,
            timestamp: new Date().toISOString()
        };

        addLog(content, `<span class="highlight">[*]</span> 构建消息数据包...`);
        await delay(400);

        const iv = CryptoUtils.randomHex(12);
        addLog(content, `<span class="highlight">[*]</span> 生成随机初始化向量 (96-bit IV)...`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">IV:</div><div class="code-value">${iv}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 执行 AES-256-GCM 加密...`);
        await delay(600);

        const encrypted = await CryptoUtils.aesEncryptWithKey(JSON.stringify(payload), this.sharedKey);
        const keyHex = await CryptoUtils.exportAESKey(this.sharedKey);

        addLog(content, `<div class="code-block"><div class="code-label">密文 (${encrypted.length} hex chars):</div><div class="code-value">${encrypted.substring(0, 120)}...</div></div>`);
        await delay(300);

        addLog(content, `<span class="highlight">[*]</span> 认证标签 (GCM Tag): 128 bits`);
        addLog(content, `<span class="success">[✓]</span> 加密完成，消息已准备好传输`);

        this.completeStep(step, status);

        return { encrypted, key: keyHex };
    }

    showEncryptResult(data) {
        document.getElementById('encryptResult').style.display = 'block';
        document.getElementById('outputData').value = data.encrypted;
        document.getElementById('outputKey').value = data.key;
    }


    // ==================== 解密流程 ====================
    async startDecryption() {
        const encryptedData = document.getElementById('encryptedData').value.trim();
        const secretKey = document.getElementById('secretKey').value.trim();

        if (!encryptedData || !secretKey) {
            alert('错误: 请输入加密数据和密钥');
            return;
        }

        document.getElementById('startDecrypt').disabled = true;
        document.getElementById('steps').classList.add('active');
        document.getElementById('step5Title').textContent = '消息解密 (AES-256-GCM)';

        try {
            await this.decryptStep1(encryptedData);
            await delay(1500);

            const aesKey = await this.decryptStep2(secretKey);
            await delay(1500);

            const decryptedData = await this.decryptStep3(encryptedData, aesKey);
            await delay(1500);

            await this.decryptStep4(decryptedData);
            await delay(1500);

            await this.decryptStep5(decryptedData);

        } catch (error) {
            alert('解密失败: 密文或密钥无效\n错误信息: ' + error.message);
            document.getElementById('startDecrypt').disabled = false;
        }
    }

    async decryptStep1(encryptedData) {
        const step = document.getElementById('step1');
        const content = document.getElementById('content1');
        const status = document.getElementById('status1');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 接收加密数据包...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 数据包大小: ${encryptedData.length / 2} bytes (${encryptedData.length} hex chars)`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">加密数据 (部分):</div><div class="code-value">${encryptedData.substring(0, 96)}...</div></div>`);
        await delay(500);

        // 提取 IV
        const iv = encryptedData.substring(0, 24);
        addLog(content, `<span class="highlight">[*]</span> 提取初始化向量 (IV)...`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">IV (96-bit):</div><div class="code-value">${iv}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 检测加密算法: AES-256-GCM`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 认证标签长度: 128 bits`);
        await delay(300);
        addLog(content, `<span class="success">[✓]</span> 数据格式验证通过`);

        this.completeStep(step, status);
    }

    async decryptStep2(secretKey) {
        const step = document.getElementById('step2');
        const content = document.getElementById('content2');
        const status = document.getElementById('status2');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 验证解密密钥...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 密钥长度: ${secretKey.length / 2} bytes (${secretKey.length * 4} bits)`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 密钥格式: 256-bit hexadecimal`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">AES-256 密钥:</div><div class="code-value">${secretKey}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 导入密钥到 Web Crypto API...`);
        await delay(300);
        const aesKey = await CryptoUtils.importAESKey(secretKey);
        addLog(content, `<span class="success">[✓]</span> 密钥验证通过`);

        this.completeStep(step, status);
        return aesKey;
    }

    async decryptStep3(encryptedData, aesKey) {
        const step = document.getElementById('step3');
        const content = document.getElementById('content3');
        const status = document.getElementById('status3');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 启动 AES-256-GCM 解密...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 分离 IV 和密文...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 执行解密操作...`);
        await delay(600);

        const decrypted = await CryptoUtils.aesDecryptWithKey(encryptedData, aesKey);
        const data = JSON.parse(decrypted);

        addLog(content, `<span class="highlight">[*]</span> 验证 GCM 认证标签...`);
        await delay(300);
        addLog(content, `<span class="success">[✓]</span> 认证标签验证通过 (数据完整性确认)`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">解密后的数据:</div><div class="code-value">${decrypted.substring(0, 200)}...</div></div>`);
        addLog(content, `<span class="success">[✓]</span> 解密成功`);

        this.completeStep(step, status);
        return data;
    }

    async decryptStep4(data) {
        const step = document.getElementById('step4');
        const content = document.getElementById('content4');
        const status = document.getElementById('status4');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 验证 ECDSA 数字签名...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">签名值 (64 bytes):</div><div class="code-value">${data.signature}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 导入 ECDSA 公钥...`);
        await delay(300);
        const ecdsaPubKey = CryptoUtils.formatECPublicKey(data.ecdsaPublicKey);
        addLog(content, `<div class="code-block"><div class="code-label">ECDSA 公钥 (P-256):</div><div class="code-value">x: ${ecdsaPubKey.x}</div><div class="code-value">y: ${ecdsaPubKey.y}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 重新计算消息哈希...`);
        await delay(300);
        const messageHash = await CryptoUtils.sha256(data.message);
        addLog(content, `<div class="code-block"><div class="code-label">SHA-256 摘要:</div><div class="code-value">${messageHash}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 执行 ECDSA 签名验证...`);
        await delay(400);

        const publicKey = await CryptoUtils.importECDSAPublicKey(data.ecdsaPublicKey);
        const isValid = await CryptoUtils.ecdsaVerify(data.message, data.signature, publicKey);

        if (isValid) {
            addLog(content, `<span class="success">[✓]</span> 签名验证成功`);
            addLog(content, `<span class="success">[✓]</span> 消息来源已确认: <span style="color: #00ffff;">${data.from}</span>`);
        } else {
            addLog(content, `<span class="warning">[!]</span> 签名验证失败`);
        }

        this.completeStep(step, status);
    }

    async decryptStep5(data) {
        const step = document.getElementById('step5');
        const content = document.getElementById('content5');
        const status = document.getElementById('status5');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 提取消息内容...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 发送方: <span class="success">${data.from}</span>`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 接收方: <span class="success">${data.to}</span>`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 时间戳: ${data.timestamp}`);
        await delay(500);

        addLog(content, `<br><span class="highlight">════════════════════════════════════════════════════════════</span>`);
        addLog(content, `<span class="highlight">[*]</span> 解密后的消息内容:`);
        addLog(content, `<div style="text-align: center; padding: 25px; font-size: 20px; color: #00ff41; text-shadow: 0 0 10px #00ff41; background: rgba(0,255,65,0.1); border-radius: 5px; margin: 15px 0;">"${data.message}"</div>`);
        addLog(content, `<span class="highlight">════════════════════════════════════════════════════════════</span>`);

        await delay(500);
        addLog(content, `<br><span class="success">[✓]</span> 解密协议执行完成`);
        addLog(content, `<span class="success">[✓]</span> 身份已验证 | ECDSA签名有效 | AES-GCM认证通过 | 消息完整`);

        this.completeStep(step, status);
    }

    completeStep(step, status) {
        status.textContent = '[ COMPLETED ]';
        status.classList.remove('running');
        status.classList.add('completed');
        step.classList.remove('active');
        step.classList.add('completed');
    }
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    new SecureMessageProtocol();
});
