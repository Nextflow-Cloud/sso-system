import Database from "../classes/ExpressDB.js";

export default new Database.Schema("forgotPasswords", {
    idHash: String,
    emailEncrypted: String,
    expires: Date
}); 
