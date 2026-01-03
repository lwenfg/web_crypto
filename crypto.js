// 密码学工具类
class CryptoUtils {
    // 生成大素数 (简化版，实际应用需要更大的素数)
    static generatePrime() {
        const primes = [
            104729, 104743, 104759, 104761, 104773,
            104779, 104789, 104801, 104803, 104827
        ];
        return primes[Math.floor(Math.random() * primes.length)];
    }

    // 模幂运算
    static modPow(base, exp, mod) {
        let result = BigInt(1);
        base = BigInt(base) % BigInt(mod);
        exp = BigInt(exp);
        mod = BigInt(mod);
        
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp / 2n;
            base = (base * base) % mod;
        }
        return Number(result);
    }

    // 生成随机私钥
    static generatePrivateKey(max) {
        return Math.floor(Math.random() * (max - 2)) + 2;
    }

    // SHA-256 哈希
    static async sha256(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // 简化的RSA密钥生成
    static generateRSAKeys() {
        // 使用较小的素数进行演示
        const p = 61;
        const q = 53;
        const n = p * q; // 3233
        const phi = (p - 1) * (q - 1); // 3120
        const e = 17; // 公钥指数
        
        // 计算私钥 d (e * d ≡ 1 mod phi)
        let d = 1;
        while ((e * d) % phi !== 1) {
            d++;
        }
        // d = 2753
        
        return {
            publicKey: { e, n },
            privateKey: { d, n }
        };
    }

    // RSA签名 (简化版)
    static rsaSign(messageHash, privateKey) {
        // 取哈希的前几位作为数字
        const hashNum = parseInt(messageHash.substring(0, 4), 16) % privateKey.n;
        return this.modPow(hashNum, privateKey.d, privateKey.n);
    }

    // RSA验签
    static rsaVerify(signature, messageHash, publicKey) {
        const hashNum = parseInt(messageHash.substring(0, 4), 16) % publicKey.n;
        const decrypted = this.modPow(signature, publicKey.e, publicKey.n);
        return decrypted === hashNum;
    }

    // AES加密 (使用Web Crypto API)
    static async aesEncrypt(plaintext, keyHex) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        // 从hex字符串生成密钥
        const keyBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = parseInt(keyHex.substr(i * 2, 2), 16) || 0;
        }
        
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );
        
        // 合并IV和密文
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        return Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // AES解密
    static async aesDecrypt(ciphertextHex, keyHex) {
        // 从hex转换回字节
        const combined = new Uint8Array(ciphertextHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
        
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        
        // 从hex字符串生成密钥
        const keyBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = parseInt(keyHex.substr(i * 2, 2), 16) || 0;
        }
        
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        
        return new TextDecoder().decode(decrypted);
    }

    // 生成随机十六进制字符串
    static randomHex(length) {
        const bytes = crypto.getRandomValues(new Uint8Array(length / 2));
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}
