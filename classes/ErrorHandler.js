const database = require('./ExpressDB');
const Crypto = require("./Crypto");
const dec = require('tweetnacl-util').decodeBase64;
const KEY = dec(process.env.KEY)
//const KEY = Buffer.from(process.env.KEY, "base64");

class ErrorHandler {
    error;
    code;
    schema = new database.Schema('error_codes', {
        code: String,
        name: String,
        message: String,
        stack: String,
        stringified: String
    });

    constructor(error) {
        if (!(error instanceof Error)) {
            throw new Error('You must have a error in the constructor.');
        }

        this.error = error;
        this.nameEncrypted = Crypto.encrypt(error.name, KEY);
        this.messageEncrypted = Crypto.encrypt(error.message, KEY);
        this.stackEncrypted = Crypto.encrypt(error.stack, KEY);
        this.stringifiedEncrypted = Crypto.encrypt(error.toString(), KEY);
    }
}

module.exports = ErrorHandler;