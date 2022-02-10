const { Schema } = require('../classes/ExpressDB');

module.exports = new Schema('profile', {
    idHash: String,
    emailHash: String,
    emailEncrypted: String,
    emailPublic: String,
    emailPublicSignature: String,
    descriptionEncrypted: String,
    websiteEncrypted: String
});