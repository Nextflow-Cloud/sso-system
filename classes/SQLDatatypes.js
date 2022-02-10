/*
 * ExpressSQL Datatypes - Datatypes for SQL purposes of the ExpressSQL engine
 * Copyright (c) 2022 Nextflow Technologies B.V. All rights reserved.
 * 
 */

/**
 * INTEGER - A SQL data type representation for Integers
 */
 class INTEGER extends Number {
    number;
    constructor(number) {
        if (number) {
            this.number = number;
        } else {
            this.number = Number.MAX_VALUE;
        }
        super(this.number);
    }
}

/**
 * INTEGER_AUTOINCREMENT - A SQL data type representation for Integers that auto increment
 */
class INTEGER_AUTOINCREMENT extends Number {
    number;
    constructor(number) {
        if (number) {
            this.number = number;
        } else {
            this.number = Number.MAX_VALUE;
        }
        super(this.number);
    }
}

/**
 * TEXT - A SQL data type representation for a String in MYSQL
 */

class TEXT extends String {
    text;
    constructor(text) {
        if (typeof text === 'string') {
            this.text = text;
        } else {
            this.text = '';
        }
        super(this.text);
    }
}

/**
 * LONGTEXT - A SQL data type representation for a String that is extremely long in MYSQL
 */

class LONGTEXT extends String {
    text;
    constructor(text) {
        if (typeof text === 'string') {
            this.text = text;
        } else {
            this.text = '';
        }
        super(this.text);
    }
}

/**
 * VARCHAR - A SQL data type representation for a String in MYSQL using VARCHAR with a variable string limit
 */

class VARCHAR extends String {
    text;
    length;
    constructor(length, text) {
        if (typeof length === 'number' || length !== 0) {
            this.length = length;
        } else {
            this.length = 255;
        }
        if (typeof text === 'string') {
            if (text.length <= length) {
                this.text = text;
            } else {
                throw new SQLDataTypeError("Can\'t have a varchar max value smaller than the length of the string.");
            }
        } else {
            this.text = '';
        }
        super(this.text);
    }
}

/**
 * SQLDataTypeError - Class that is thrown when there is an error with the SQL data type provided.
 */
class SQLDataTypeError extends Error {
    message = '';
    name = '';
    constructor(message, name) {
        super(message);
        if (typeof name !== 'string') {
            this.name = 'SQLDataTypeError';
        } else {
            this.name = name;
        }
        this.message = message;
    }
}

module.exports = {
    SQLDataTypeError,
    VARCHAR,
    LONGTEXT,
    TEXT,
    INTEGER_AUTOINCREMENT,
    INTEGER
}