const { Schema } = require('../classes/ExpressDB');

module.exports = new Schema('blacklist', {
    emailHash: String,
    tokenHash: String
});
