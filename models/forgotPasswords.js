const { Schema } = require("../classes/ExpressDB");

module.exports = new Schema('forgotPasswords', {
    idHash: String,
    emailEncrypted: String,
    expires: Date
}); 
