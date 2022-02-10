const { Schema } = require('../classes/ExpressDB');

module.exports = new Schema('avatar', {
    idHash: String,
    emailHash: String,
    fileName: String,
    fileType: String,
    originalName: String,
});