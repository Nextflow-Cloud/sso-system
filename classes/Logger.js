import fs from "fs";

import chalk from "chalk";

import Database from './ExpressDB.js';
import Crypto from "./Crypto.js";
import LoggerError from './LoggerError.js';

const SERVER_PRIVATE_KEY = process.env.PRIVATE;
const KEY = Buffer.from(process.env.KEY, "base64");

class Logger {
    constructor() {
        this.databaseErrors = new Database.Schema("errors", {
            id: String,
            idSignature: String,
            nameEncrypted: String,
            messageEncrypted: String,
            stackEncrypted: String,
            stringifiedEncrypted: String,
            date: Date
        });
        if (!fs.existsSync("./logs")) fs.mkdirSync("./logs");
        this.logStream = fs.createWriteStream(`./logs/log_${this.dateString(new Date())}.log`, { flags: "a" });
        this.console = console;
        global.console = this;
        this.enhancedLog("Logger", "The logger has been instantiated and started.");
        // fs.writeFileSync(`run_${this.dateString(new Date())}.log`, log);
    }
    log(...log) {
        const logString = `[LOG: Logger.General] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.log(logString);
        this.logStream.write(logString + "\n");
    }
    enhancedLog(aspect, ...log) {
        const logString = `[LOG: ${aspect}] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.log(logString);
        this.logStream.write(logString + "\n");
    }
    error(error) {
        if (!(error instanceof Error)) throw new LoggerError("You must have a error in the constructor.");
        // if (!this.databaseErrors.database.connected) {
            // this.enhancedWarn("Logger", 'Database is not connected.'); 
        // }
        var id = Crypto.generateID(15, '0123456789');

        const errorObj = {
            nameEncrypted: Crypto.encrypt(error.name, KEY), 
            messageEncrypted: Crypto.encrypt(error.message, KEY),
            stackEncrypted: Crypto.encrypt(error.stack, KEY),
            stringifiedEncrypted: Crypto.encrypt(error.toString(), KEY),
            date: new Date(),
            id,
            idSignature: Crypto.sign(id, SERVER_PRIVATE_KEY)
        };

        this.databaseErrors.create(errorObj);
        const logString = `[ERROR: Logger.General] (${this.dateString(new Date())}) ${error.toString()} [ID: ${id}]`;
        this.console.log(chalk.whiteBright(chalk.bgRedBright(logString)));
        this.logStream.write(logString + "\n");
    }

    enhancedError(aspect, error) {
        if (!(error instanceof Error)) throw new Error("You must have a error in the constructor.");
        // if (!this.databaseErrors.client.connected) {
        //     throw new Error('Database is not connected.');
        // }
        var id = Crypto.generateID(15, '0123456789');

        const errorObj = {
            nameEncrypted: Crypto.encrypt(error.name, KEY),
            messageEncrypted: Crypto.encrypt(error.message, KEY),
            stackEncrypted: Crypto.encrypt(error.stack, KEY),
            stringifiedEncrypted: Crypto.encrypt(error.toString(), KEY),
            date: new Date(),
            id,
            idSignature: Crypto.sign(id, SERVER_PRIVATE_KEY)
        };
        this.databaseErrors.create(errorObj);
        const logString = `[ERROR: ${aspect}] (${this.dateString(new Date())}) ${error.toString()} [ID: ${id}]`;
        this.console.log(chalk.whiteBright(chalk.bgRed(logString)));
        this.logStream.write(logString + "\n");
    }

    warn(...log) {
        const logString = `[WARN: Logger.General] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.warn(chalk.whiteBright(chalk.bgYellowBright(logString)));
        this.logStream.write(logString + "\n");
    }
    enhancedWarn(aspect, ...log) {
        const logString = `[WARN: ${aspect}] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.warn(chalk.whiteBright(chalk.bgYellowBright(logString)));
        this.logStream.write(logString + "\n");
    }
    info(...log) {
        const logString = `[INFO: Logger.General] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.info(chalk.whiteBright(chalk.bgBlueBright(logString)));
        this.logStream.write(logString + "\n");
    }
    enhancedInfo(aspect, ...log) {
        const logString = `[INFO: ${aspect}] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.info(chalk.whiteBright(chalk.bgBlueBright(logString)));
        this.logStream.write(logString + "\n");
    }
    debug(...log) {
        const logString = `[DEBUG: Logger.General] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.debug(chalk.whiteBright(chalk.bgCyanBright(logString)));
        this.logStream.write(logString + "\n");
    }
    enhancedDebug(aspect, ...log) {
        const logString = `[DEBUG: ${aspect}] (${this.dateString(new Date())}) ${log.join(" ")}`;
        this.console.debug(chalk.whiteBright(chalk.bgCyanBright(logString)));
        this.logStream.write(logString + "\n");
    }
    dateString(date) {
        if (!(date instanceof Date)) throw new LoggerError("Not a date.");
        let format = "MM-dd-yyyy_hh-mm-ss";
        var conversion = {
            M: date.getMonth() + 1,
            d: date.getDate(),
            h: date.getHours(),
            m: date.getMinutes(),
            s: date.getSeconds()
        }
        format = format.replace(/(M+|d+|h+|m+|s+)/g, v => ((v.length > 1 ? "0" : "") + conversion[v.slice(-1)]).slice(-2));
        return format.replace(/(y+)/g, v => date.getFullYear().toString().slice(-v.length));
    }
    // we can work on this later.

    // async getId() {
    // }
    // async getError(id, pwd) {
    //     if (typeof id !== 'string') {
    //         throw new ErrorError('Not a VALID id.')
    //     }
    //     if (Crypto.veifyPassword(pwd, process.env.hashed))
    // }
    // ok also we switch to fastify soon
    // sudo nano /snap/bin/npm
    // new Server(port, uri, encryptionOptions, log = "VERBOSE")
}

export default Logger;
