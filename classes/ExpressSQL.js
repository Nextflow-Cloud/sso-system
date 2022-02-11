import DatabaseError from "./DatabaseError.js";
import { EventEmitter } from "events";
import mysql from "mysql";

class SQL extends EventEmitter {
    database;
    user;
    password;
    host;
    connected;
    checkDb;
    constructor (host, user, password, database, uri) {
        if (uri) {
            this.parse(uri);
        } else {
            if ([host, user, password, database].map(i => typeof i).every(i => i === "string")) {
                this.host = host;
                this.database = database;
                this.user = user;
                this.password = password;
            }
        }
        this.connected = false;
    }
    async initiate() {
        try {
            this.checkDb = mysql.createConnection({
                host: this.host,
                user: this.user,
                password: this.password
            });
        } catch (e) {
            throw new DatabaseError("Database could not connect, please check your credentials." + e.message);
        }
        await this.createDb().catch(e => {
            throw new DatabaseError("An error occurred " + e.message);
        });
        this.checkDb.end(); 
        this.connection = mysql.createConnection({
            user: this.user,
            password: this.password,
            database: this.database,
            host: this.host
        });
        this.connection.connect(e => {
            if (e) this.emit("error", e);
            else {
                this.emit("connected");
                SQL.globalConnection = this.connection;
                this.connected = true;
            }
        });
    }
    parse(uri) {
        if (typeof uri !== "string") {
            throw new DatabaseError("Sql uri is invalid, please input a valid uri.");
        }
        // expresssql://user:password@host:port/db?
        let format = /expresssql:\/\/([a-zA-Z0-9]+):([a-zA-Z0-9]+)@(.+):([0-9]{2,5})\/(.*)/m;
        if (format.test(uri)) {
            let values = uri.match(format);
            this.user = values[1];
            this.password = values[2];
            this.host = values[3] + ":" + values[4];
            this.database = values[5];
        } else {
            throw new DatabaseError("SQL uri is invalid, please input a valid uri.");
        }
    }
    createDb() {
        if (this.checkDb) {
            return new Promise((resolve, reject) => {
                this.checkDb.query("CREATE DATABASE :db IF NOT exists :db", { db: "fuckyousql123" }, (e, r) => {
                    if (e) reject(e);
                    else resolve(r);
                });
            });
        } else {
            throw new DatabaseError("Check database is nonexistent or undefined.");
        }
    }
    close() {
        if (this.connected) {
            this.connection.end(e => {
                if (e) this.emit("error", e);
                else this.emit("end");
            });
        } else {
            throw new DatabaseError("You are not connected to the database connections. Cannot close a non-existant connection.");
        }
    }
}

class Table {
    schemaObj;
    schemaObjFormatted;
    name;
    connection;
    typeList = [];
    tableString = "";
    constructor(name, schemaObj) {
        if (!this.connection) {
            throw new DatabaseError("No connection to the mysql database, can't use tables without connection.");
        }
        this.connection = SQL.globalConnection;
        this.name = name;
        if (!schemaObj) {
            throw new DatabaseError("No schema object passed.");
        }
        if (typeof schemaObj !== "object") {
            throw new DatabaseError("Invalid schema object passed");
        }
        parse();
    }
    parse() {
        this.conversionTypes = {
            "String": "text",
            "Number": "int",
            "Boolean": "boolean",
            "null": "bit(0)",
            "undefined": "bit(0)"
        };
        this.typeConversions = {};
        this.schemaObjFormatted = {};
        Object.entries(this.conversionTypes).forEach(v => {
            this.typeConversions[v[1]] = v[0];
        });
        Object.entries(this.schemaObj).forEach(v => {
            if (this.conversionTypes[v[1].constructor.name] === undefined) {
                throw new DatabaseError("Not a valid object given, please use valid object.");
            }
            this.schemaObjFormatted[v[0]] = conversionTypes[v[1].constructor.name];
        });
    }
    async create() {
        this.tableString = `CREATE TABLE ? (`;
        let entries = Object.entries(this.schemaObjFormatted);
        this.typeList = [];
        for (let i = 0; i < entries.length; i++) {
            this.typeList.push(entries[i][0]);
            this.typeList.push(entries[i][1]);
            if (i === (entries.length - 1)) {
                this.tableString += "? ?";
            } else {
                this.tableString += "? ?, ";
            }
        }
        this.tableString += ")";
        let params = [];
        for (let i = 0; i < entries.length; i++) {
            params.push(entries[i][0]);
            params.push(entries[i][1]);
        }
        await this.connection.query(this.tableString, params);
    }
}

SQL.Table = Table;
export default SQL;
