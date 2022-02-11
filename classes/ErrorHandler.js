import database from './ExpressDB.js';
import Crypto from "./Crypto.js";
const KEY = Buffer.from(process.env.KEY, "base64");

class ErrorHandler {
    error;
    nameEncrypted;
    messageEncrypted;
    stackEncrypted;
    stringifiedEncrypted;
    errorSchema;

    constructor(error) {
        if (!(error instanceof Error)) {
            throw new Error('You must have a error in the constructor.');
        }

        this.errorSchema = new database.Schema({
            id: String,
            idSignature: String,
            nameEncrypted: String,
            messageEncrypted: String,
            stackEncrypted: String,
            stringifiedEncrypted: String
        });

        this.error = error;
        this.nameEncrypted = Crypto.encrypt(error.name, KEY);
        this.messageEncrypted = Crypto.encrypt(error.message, KEY);
        this.stackEncrypted = Crypto.encrypt(error.stack, KEY);
        this.stringifiedEncrypted = Crypto.encrypt(error.toString(), KEY);
        this.id = Crypto.generateID(15, '0123456789');
        this.idSignature

        // console.log(this.id)


    }
}

module.exports = ErrorHandler;