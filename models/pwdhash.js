import Database from "../classes/ExpressDB.js";

export default new Database.Schema("pwdHashes", {
    emailHash: String,
    fileName: String,
    fileType: String,
    originalName: String,
});
