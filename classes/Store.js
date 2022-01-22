const Database = require('./ExpressDB.js');
const Crypto = require("./Crypto");
const dec = require('tweetnacl-util').decodeBase64;
const KEY = dec(process.env.KEY)

/**
 * Store - a temporary container for data
 */
class Store {
    name;
    schema;
    dbclient = Database.globalClient;
    constructor(name) {
        this.schema = new Database.Schema(name, {
            name: String,
            key: String,
            value: Object
        });
        this.name = name;
    }
    store(key, value) {
        return Crypto.hashPasswordSalt(key, process.env.SALT_T).then(hashedKey => {
            const newObject = Object.fromEntries(Object.entries(value).map(v => {
                const primitiveTypes = ["String", "Number", "Boolean", "undefined", "null", "Date"];
                if (primitiveTypes.includes(v[1].constructor.name)) {
                    if (typeof v[1] === "undefined" || v[1] === null) {
                        return [v[0], "null"];
                    } else {
                        return [v[0], v[1].constructor.name + ':' + v[1].toString()];
                    }
                } else {
                    return [v[0], "null"];
                }
            }).map(v => {
                const encValue = Crypto.encrypt(v[1], KEY);
                return [v[0], encValue];
            }));
            return this.schema.insertOne({
                name: this.name,
                key: hashedKey,
                value: newObject
            }); 
        });
    }
    get(key) {
        return Crypto.hashPasswordSalt(key, process.env.SALT_T).then(hashedKey => this.schema.findOne({
            name: this.name,
            key: hashedKey
        }).then(result => {
            if (result) {
                const decryptedObject = Object.fromEntries(Object.entries(result.value).map(v => {
                    if (v[1] === null) {
                        return v; 
                    } else {
                        const value = Crypto.decrypt(v[1], KEY);
                        if (value.includes(':')) {
                            const split = value.split(':');
                            const name = split.shift();
                            const primitiveTypes = ["String", "Number", "Boolean"];
                            if (name.toLowerCase() === "date") { 
                                return [v[0], new Date(split.join(':'))]; 
                            } else if (primitiveTypes.includes(name)) {
                                const str = split.join(':');
                                const value = eval(`${primitiveTypes.find(t => name === t)}(str)`);
                                return [v[0], value];
                            }
                        } else {
                            return [v[0], null];
                        }
                    }
                }));
                return decryptedObject;
            } else {
                return null;
            }
        }));
    }
}

module.exports = Store;
