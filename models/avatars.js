import Database from "../classes/ExpressDB.js";

export default new Database.Schema("avatars", {
    idHash: String,
    emailHash: String,
    fileName: String,
    fileType: String,
    originalName: String,
});
