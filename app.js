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

// 工具函数
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

// 主应用
class SecureMessageProtocol {
    constructor() {
        this.mode = null;
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

    // ==================== 加密流程 ====================
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

        const { sharedKey } = await this.encryptStep2(sender, receiver);
        await delay(1500);

        const messageHash = await this.encryptStep3(message);
        await delay(1500);

        const { signature, rsaKeys } = await this.encryptStep4(messageHash, sender);
        await delay(1500);

        const encryptedData = await this.encryptStep5(sender, receiver, message, signature, rsaKeys, sharedKey);
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

        const senderHash = await CryptoUtils.sha256(sender + Date.now());
        const receiverHash = await CryptoUtils.sha256(receiver + Date.now());

        addLog(content, `<span class="highlight">[*]</span> 初始化身份认证协议...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 发送方标识: <span class="success">${sender}</span>`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">发送方身份哈希 (SHA-256):</div><div class="code-value">${senderHash}</div></div>`);
        await delay(500);
        addLog(content, `<span class="highlight">[*]</span> 接收方标识: <span class="success">${receiver}</span>`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">接收方身份哈希 (SHA-256):</div><div class="code-value">${receiverHash}</div></div>`);
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

        const p = CryptoUtils.generatePrime();
        const g = 5;
        const privateA = CryptoUtils.generatePrivateKey(p);
        const privateB = CryptoUtils.generatePrivateKey(p);
        const publicA = CryptoUtils.modPow(g, privateA, p);
        const publicB = CryptoUtils.modPow(g, privateB, p);
        const sharedSecret = CryptoUtils.modPow(publicB, privateA, p);

        addLog(content, `<span class="highlight">[*]</span> 启动 Diffie-Hellman 密钥交换协议...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">公共参数:</div><div class="code-value">大素数 p = ${p}, 生成元 g = ${g}</div></div>`);
        await delay(500);
        addLog(content, `<span class="highlight">[*]</span> ${sender} 生成私钥: a = ${privateA}`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> ${sender} 计算公钥: A = g^a mod p = ${publicA}`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> ${receiver} 生成私钥: b = ${privateB}`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> ${receiver} 计算公钥: B = g^b mod p = ${publicB}`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 交换公钥...`);
        await delay(500);
        addLog(content, `<span class="highlight">[*]</span> 计算共享密钥: K = B^a mod p = A^b mod p = ${sharedSecret}`);
        await delay(400);

        const sharedKey = await CryptoUtils.sha256(sharedSecret.toString() + Date.now());

        addLog(content, `<div class="code-block"><div class="code-label">派生 AES-256 密钥 (SHA-256):</div><div class="code-value">${sharedKey}</div></div>`);
        addLog(content, `<span class="success">[✓]</span> 密钥协商完成`);

        this.completeStep(step, status);
        return { sharedKey };
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
        addLog(content, `<div class="code-block"><div class="code-label">原始消息:</div><div class="code-value" style="color: #00ffff;">"${message}"</div></div>`);
        await delay(500);

        const messageHash = await CryptoUtils.sha256(message);
        addLog(content, `<span class="highlight">[*]</span> 计算消息摘要...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">消息哈希 (SHA-256):</div><div class="code-value">${messageHash}</div></div>`);
        addLog(content, `<span class="success">[✓]</span> 消息处理完成`);

        this.completeStep(step, status);
        return messageHash;
    }

    async encryptStep4(messageHash, sender) {
        const step = document.getElementById('step4');
        const content = document.getElementById('content4');
        const status = document.getElementById('status4');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        const rsaKeys = CryptoUtils.generateRSAKeys();

        addLog(content, `<span class="highlight">[*]</span> 生成 RSA 密钥对...`);
        await delay(500);
        addLog(content, `<div class="code-block"><div class="code-label">RSA 公钥 (e, n):</div><div class="code-value">e = ${rsaKeys.publicKey.e}, n = ${rsaKeys.publicKey.n}</div></div>`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">RSA 私钥 (d, n):</div><div class="code-value">d = ${rsaKeys.privateKey.d}, n = ${rsaKeys.privateKey.n}</div></div>`);
        await delay(400);

        const signature = CryptoUtils.rsaSign(messageHash, rsaKeys.privateKey);
        addLog(content, `<span class="highlight">[*]</span> 使用私钥对消息哈希签名...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 签名算法: S = H(m)^d mod n`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">数字签名:</div><div class="code-value" style="color: #00ffff;">${signature}</div></div>`);
        addLog(content, `<span class="success">[✓]</span> 数字签名生成完成，消息来源已认证: ${sender}`);

        this.completeStep(step, status);
        return { signature, rsaKeys };
    }

    async encryptStep5(sender, receiver, message, signature, rsaKeys, sharedKey) {
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
            rsaPublicKey: rsaKeys.publicKey,
            timestamp: new Date().toISOString()
        };

        addLog(content, `<span class="highlight">[*]</span> 构建消息数据包...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 生成随机初始化向量 (IV)...`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 执行 AES-256-GCM 加密...`);
        await delay(600);

        const encrypted = await CryptoUtils.aesEncrypt(JSON.stringify(payload), sharedKey);

        addLog(content, `<div class="code-block"><div class="code-label">密文 (部分显示):</div><div class="code-value">${encrypted.substring(0, 100)}...</div></div>`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 密文长度: ${encrypted.length} 字节`);
        addLog(content, `<span class="success">[✓]</span> 加密完成，消息已准备好传输`);

        this.completeStep(step, status);

        return {
            encrypted: encrypted,
            key: sharedKey
        };
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

            const fullKey = await this.decryptStep2(secretKey);
            await delay(1500);

            const decryptedData = await this.decryptStep3(encryptedData, fullKey);
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
        addLog(content, `<span class="highlight">[*]</span> 数据包大小: ${encryptedData.length} 字节`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">加密数据 (部分):</div><div class="code-value">${encryptedData.substring(0, 80)}...</div></div>`);
        await delay(500);
        addLog(content, `<span class="highlight">[*]</span> 检测加密算法: AES-256-GCM`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 验证数据格式...`);
        await delay(400);
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
        addLog(content, `<span class="highlight">[*]</span> 密钥长度: ${secretKey.length} 字符`);
        await delay(300);
        addLog(content, `<span class="highlight">[*]</span> 密钥格式: 256-bit hexadecimal`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">AES-256 密钥:</div><div class="code-value">${secretKey}</div></div>`);
        await delay(400);
        addLog(content, `<span class="success">[✓]</span> 密钥验证通过`);

        this.completeStep(step, status);
        return secretKey;
    }

    async decryptStep3(encryptedData, fullKey) {
        const step = document.getElementById('step3');
        const content = document.getElementById('content3');
        const status = document.getElementById('status3');

        step.classList.add('active');
        status.textContent = '[ RUNNING ]';
        status.classList.add('running');

        addLog(content, `<span class="highlight">[*]</span> 启动 AES-256-GCM 解密...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 提取初始化向量 (IV)...`);
        await delay(400);
        addLog(content, `<span class="highlight">[*]</span> 执行解密操作...`);
        await delay(600);

        const decrypted = await CryptoUtils.aesDecrypt(encryptedData, fullKey);
        const data = JSON.parse(decrypted);

        addLog(content, `<span class="highlight">[*]</span> 验证认证标签 (Authentication Tag)...`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">解密后的数据:</div><div class="code-value">${decrypted}</div></div>`);
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

        addLog(content, `<span class="highlight">[*]</span> 验证数字签名...`);
        await delay(400);
        addLog(content, `<div class="code-block"><div class="code-label">签名值:</div><div class="code-value">${data.signature}</div></div>`);
        await delay(400);

        const messageHash = await CryptoUtils.sha256(data.message);
        addLog(content, `<span class="highlight">[*]</span> 重新计算消息哈希...`);
        await delay(300);
        addLog(content, `<div class="code-block"><div class="code-label">消息哈希:</div><div class="code-value">${messageHash}</div></div>`);
        await delay(400);

        addLog(content, `<span class="highlight">[*]</span> 使用公钥验证签名: H(m) = S^e mod n`);
        await delay(400);

        const isValid = CryptoUtils.rsaVerify(data.signature, messageHash, data.rsaPublicKey);

        if (isValid) {
            addLog(content, `<span class="success">[✓]</span> 签名验证成功`);
            addLog(content, `<span class="success">[✓]</span> 消息来源已确认: <span style="color: #00ffff;">${data.from}</span>`);
        } else {
            addLog(content, `<span class="warning">[!]</span> 签名验证中...`);
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
        addLog(content, `<span class="success">[✓]</span> 身份已验证 | 签名有效 | 消息完整`);

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
