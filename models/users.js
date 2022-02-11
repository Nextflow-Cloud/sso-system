import Database from "../classes/ExpressDB.js";

export default new Database.Schema("logins", {
    idHash: String,
    idEncrypted: String,
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
