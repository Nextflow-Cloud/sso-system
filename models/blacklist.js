import Database from "../classes/ExpressDB.js";

export default new Database.Schema("blacklist", {
    emailHash: String,
    tokenHash: String
});
