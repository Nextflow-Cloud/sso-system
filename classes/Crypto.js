/*
 * Crypto - a secure module for cryptographic functions
 * Copyright (c) 2022 Nextflow Technologies B.V. All rights reserved.
 * 
 */

const crypto = require('crypto');
const dotenv = require('dotenv');
dotenv.config();
const bcrypt = require('bcrypt');

const KEY = Buffer.from(process.env.KEY, "base64");
const SERVER_PRIVATE_KEY = process.env.PRIVATE;
const SERVER_PUBLIC_KEY = process.env.PUBLICKEY;
const IV = Buffer.from(process.env.IV, "base64");
const fs = require('fs');

/**
 * Crypto - a handler for cryptographic functions. Securely handles cryptographic functions of the server, such as the encryption and decryption of data
 */
class Crypto {
    static async hashFile(pathOf) {
        let file = fs.readFileSync(pathOf);
        let hashSum = crypto.createHash('sha256');
        hashSum.update(file);
        return hashSum.digest('base64')
    }
    // Bcrypt functions
    static async verifyPassword(password, passwordHash) {
        try {
            return await bcrypt.compare(password, passwordHash);
        } catch (error) {
            throw error;
        }
        return null;
    }
    static async hashPassword(password) {
        try {
            return await bcrypt.hash(password, await bcrypt.genSalt(10));
        } catch (error) {
            throw error;
        }
        return null;
    }
    static async hashPasswordSalt(password, salt = process.env.SALT) { 
        try {
            return await bcrypt.hash(password, Buffer.from(salt, "base64").toString("utf-8"));
        } catch (error) {
            throw error;
        }
        return null;
    }

    // RSA functions
    static encryptRSA(input, pKey = SERVER_PUBLIC_KEY) {
        let text = Buffer.from(input);
        let ciphertext = crypto.publicEncrypt(pKey, text);
        return ciphertext.toString("base64");
    }
    static decryptRSA(input, pKey = SERVER_PRIVATE_KEY) {
        let text = Buffer.from(input, "base64");
        let decrypted = crypto.privateDecrypt(pKey, text);
        return decrypted.toString("utf8");
    }
    static sign(encdata, pKey = process.env.PRIVATE) {
        return crypto.sign('RSA-SHA256', Buffer.from(encdata), pKey).toString('base64');
    }
    static verify(encdata, signature, pKey = process.env.PUBLIC) {
        return crypto.verify('RSA-SHA256', encdata, pKey, Buffer.from(signature, 'base64'));
    }
    
    // AES functions
    static encrypt(data, key, ivaa=null) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let ciphered = cipher.update(data, 'utf-8', 'binary');
        ciphered += cipher.final('binary'); 
        return Buffer.concat([iv, Buffer.from(ciphered, 'binary')]).toString('base64');
    }
    static decrypt(data, key, ivaaa=null) {
        const dataD = Buffer.from(data, 'base64');
        const iv = dataD.slice(0, 16);
        const dataMessage = dataD.slice(16);
        const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let ciphered = cipher.update(dataMessage, 'binary', 'utf-8');
        ciphered += cipher.final('utf-8');
        return ciphered;
    } 
    static async encryptFile(filename) {
        const cipher = crypto.createCipheriv('aes-256-cbc', KEY, IV);
        const input = fs.createReadStream(`${filename}`);
        const output = fs.createWriteStream(`${filename}.encrypted`);
        input.pipe(cipher).pipe(output);
        fs.unlink(`${filename}`, (err) => {
            if (err) {
                console.error(err);
            }
        });
        return 0;
    }
    static async decryptFile(filename) { 
        const cipher = crypto.createDecipheriv('aes-256-cbc', KEY, IV);
        const input = fs.createReadStream(`${filename}.encrypted`);
        const output = fs.createWriteStream(`${filename}`);
        input.pipe(cipher).pipe(output);
        return 0;
    }

    // Generation functions
    static random(length = 8, chars = 'ABCDEFGTHKLMNPQRSVWYZ23456789') {
        let password = '';
        for (let i = 0; i < length; i++) password += chars[crypto.randomInt(chars.length)];
        return password;
    }

    static generateID(length, chars = 'ABCDEFGHKLMNPQRSTVWYZ23456789') {
        let generated = '';
        for (let i = 0; i <= length; i++) {
            generated += chars[crypto.randomInt(chars.length)];
        }
        return generated;
    }

    static generateKey(chars = 'ABCDEFGHKLMNPQRSTVWYZ23456789') {
        let key = '';
        for (let i = 0; i <= 4; i++) {
            for (let j = 0; j <= 4; j++) {
                key += chars[crypto.randomInt(chars.length)];
            }
            key += '-';
        }
        key = Array.from(key);
        key.pop();
        key = key.join('');
        return key;
    }
    static generateBackupCodes() {
        let backup = '';
        let chars = "abcdefghijklmnopqrstuvwxyz1234567890";
        for (let i = 0; i < 10; i++) {
            backup += chars[crypto.randomInt(chars.length)];
        }
        return backup;
    }
    static async generateToken(data) { 
        let hash = Buffer.from((await this.hashPassword(crypto.randomUUID() + crypto.randomUUID()) + (await this.hashPassword(data))), 'utf-8').toString('hex');
        let str = '';
        for (let i = 8; i < hash.length; i++) {
            if (i % 8 === 0) {
                if (i !== 8) { 
                    str += '-';
                }
            } else {
                str += hash[i];
            }
        }
        str += '-' + crypto.randomUUID() + crypto.randomUUID();
        return str;
    }
}

module.exports = Crypto;
