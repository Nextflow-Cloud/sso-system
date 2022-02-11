/*
 * ExpressDB - a quick and efficient way to store data in a database
 * Copyright (c) 2022 Nextflow Technologies B.V. All rights reserved.
 * 
 */
import { MongoClient } from "mongodb";
import DatabaseError from "./DatabaseError.js";
import { EventEmitter } from "events";

/**
 * Database - a database manager for the server. Includes secure handling of database policies, and loading models and schemas.
 */

class Database extends EventEmitter {
    uri;
    connected;// dude you said sql even though it had nothing to do with this
    models;
    database;
    client;
    constructor(uri = process.env.URI, database = process.env.DB) { 
        super(); 
        this.uri = uri;
        if (!this.uri) {
            throw new DatabaseError('You must provide a URI connection string or set the URI environment variable.');
        }
        this.connected = false;
        this.models = [];
        this.database = database;
        this.client = new MongoClient(uri);
    }
    async connect() {
        await this.client.connect().then(() => {
            Database.globalClient = this.client.db(this.database);
            this.connected = true;
            this.emit("connected");
            
        }).catch(e => {
            throw new DatabaseError('Server timing out, or invalid URI. ' + e.message);
        });
    }
    getSchema(model) {
        if (!this.uri) {
            throw new DatabaseError('You did not invoke the constructor');
        }
        let schema = this.models.find(r => r.name === model);
        if (!schema) {
            throw new DatabaseError('That schema does not exist.');
        }
        return schema.model;
    }
}

/**
 * Schema - a schema for a database model.
 */
class Schema {
    collection;
    schema;
    client;
    constructor(collection, objTypes, database) {
        if (database) this.client = database.client;
        else this.client = Database.globalClient;
        this.collection = collection;
        this.schema = objTypes;
    }

    async create(object) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await this.parse(object).then(() => {
            return this.insertOne(object);
        }).catch(e => {
            throw e;
        });
    }
    async findOne(query, callback) { 
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        if (callback) {
            callback(await this.client.collection(this.collection).findOne(query));
        } else {
            return await this.client.collection(this.collection).findOne(query);
        }
    }
    async findOneAndUpdate(query, update) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await this.parse(update).then(() => this.client.collection(this.collection).findOneAndUpdate(query, { $set: update })).catch(e => {
            throw e; 
        });
    }
    async findOneAndDelete(query) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        this.client.collection(this.collection).findOneAndDelete(query);
    }
    async find(query) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        const arr = await this.client.collection(this.collection).find(query).toArray();
        console.log(arr)
        return arr;
    }
    async insertOne(obj) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await this.parse(obj).then(() => {
            return this.client.collection(this.collection).insertOne(obj);
        }).catch(e => {
            throw e;
        });
    }
    async insertMany(obj) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await Promise.all(obj.map(i => this.parse(i))).then(() => this.client.collection(this.collection).insertMany(obj)).catch(e => {
            throw e;
        });
    }
    // async updateOne(query, update) {
    // }
    // async updateMany(query, update) {
    // }
    async deleteOne(query) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await this.client.collection(this.collection).deleteOne(query); // promis is right here
    }
    async deleteMany(query) {
        if (!this.client) this.client = Database.globalClient;
        if (!this.client) throw new Error('No database connection');
        return await this.client.collection(this.collection).deleteMany(query);
    }
    // findAndModify ? 
    // https://docs.mongodb.com/manual/reference/method/js-collection/
    parse(obj) {
        return new Promise((resolve, reject) => {
            Object.keys(obj).forEach(key => {
                if (!this.schema[key]) {
                    reject(new DatabaseError('Invalid property: ' + key));
                }
                if (this.schema[key].name !== obj[key].constructor.name) {
                    reject(new DatabaseError('Invalid type for property: ' + key));
                }
                resolve(true);
            });
        }); 
    }
}

Database.Schema = Schema; 
export default Database;
