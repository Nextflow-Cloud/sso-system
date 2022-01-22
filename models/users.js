const { Schema } = require("../classes/ExpressDB");

module.exports = new Schema('logins', {
    usernameHash: String,
    usernameEncrypted: String,
    emailEncrypted: String,
    emailHash: String,
    nameEncrypted: String,
    passwordHash: String,
    twoFactorSignature: String,
    twoFactorEncrypted: String,
    twoFactorCodeEncrypted: String,
    twoFactorCodeSignature: String,
    twoFactorBackupCodesHashed: Array,
    twoFactorBackupCodesEncrypted: Array,
    twoFactorBackupCodesSignature: Array
});
