import Database from "../classes/ExpressDB.js";

export default new Database.Schema("profile", {
    idHash: String,
    emailHash: String,
    emailEncrypted: String,
    emailPublic: String,
    emailPublicSignature: String,
    descriptionEncrypted: String,
    websiteEncrypted: String
});
