/**
 * 密码学工具类 - 使用 Web Crypto API 实现真实的密码学操作
 * 
 * 包含:
 * - ECDH (Elliptic Curve Diffie-Hellman) 密钥交换 - P-256曲线
 * - ECDSA (Elliptic Curve Digital Signature Algorithm) 数字签名
 * - AES-256-GCM 对称加密
 * - SHA-256/SHA-512 哈希
 */
class CryptoUtils {
    
    // ==================== 哈希函数 ====================
    
    static async sha256(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static async sha512(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-512', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ==================== ECDH 密钥交换 (P-256曲线) ====================
    
    static async generateECDHKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        
        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            publicKeyJwk,
            privateKeyJwk
        };
    }

    static async deriveSharedKey(privateKey, publicKey) {
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: publicKey },
            privateKey,
            256
        );
        
        const sharedKeyHex = Array.from(new Uint8Array(sharedBits))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        
        // 使用 HKDF 派生 AES 密钥
        const keyMaterial = await crypto.subtle.importKey(
            'raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']
        );
        
        const aesKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new TextEncoder().encode('secure-msg-protocol'),
                info: new TextEncoder().encode('aes-256-gcm-key')
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        return { sharedKey: aesKey, sharedKeyHex };
    }

    static async importECDHPublicKey(jwk) {
        return await crypto.subtle.importKey(
            'jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []
        );
    }

    // ==================== ECDSA 数字签名 (P-256曲线) ====================
    
    static async generateECDSAKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        );
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        
        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            publicKeyJwk
        };
    }

    static async ecdsaSign(message, privateKey) {
        const data = new TextEncoder().encode(message);
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            privateKey,
            data
        );
        return Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static async ecdsaVerify(message, signatureHex, publicKey) {
        const data = new TextEncoder().encode(message);
        const signature = new Uint8Array(
            signatureHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
        );
        return await crypto.subtle.verify(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            publicKey,
            signature,
            data
        );
    }

    static async importECDSAPublicKey(jwk) {
        return await crypto.subtle.importKey(
            'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
        );
    }

    // ==================== AES-256-GCM 加密 ====================
    
    static async aesEncryptWithKey(plaintext, key) {
        const data = new TextEncoder().encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            data
        );
        
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        return Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static async aesDecryptWithKey(ciphertextHex, key) {
        const combined = new Uint8Array(
            ciphertextHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
        );
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            ciphertext
        );
        
        return new TextDecoder().decode(decrypted);
    }

    static async importAESKey(keyHex) {
        const keyBytes = new Uint8Array(
            keyHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
        );
        return await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
    }

    static async exportAESKey(key) {
        const exported = await crypto.subtle.exportKey('raw', key);
        return Array.from(new Uint8Array(exported))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ==================== 工具函数 ====================
    
    static randomHex(byteLength) {
        const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static formatECPublicKey(jwk) {
        return {
            curve: jwk.crv,
            x: jwk.x,
            y: jwk.y
        };
    }

    // 获取 DH 参数信息 (用于显示)
    static getDHParamsInfo() {
        return {
            name: 'ECDH with P-256 (secp256r1)',
            curve: 'NIST P-256',
            keySize: 256,
            securityLevel: '128-bit equivalent'
        };
    }

    // 获取签名算法信息 (用于显示)
    static getSignatureInfo() {
        return {
            name: 'ECDSA with P-256',
            hash: 'SHA-256',
            signatureSize: '64 bytes (512 bits)',
            securityLevel: '128-bit equivalent'
        };
    }
}
