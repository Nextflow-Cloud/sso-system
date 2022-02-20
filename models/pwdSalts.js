import Database from "../classes/ExpressDB.js";

export default new Database.Schema("pwdSalts", {
    emailHash: String,
    fileName: String,
    fileType: String,
    originalName: String,
});
