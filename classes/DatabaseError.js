/**
 * DatabaseError - An error class for database errors
 */

/**
 * DatabaseError - Class that is thrown when there is an error with the database.
 */
class DatabaseError extends Error {
    constructor(message) {
        super(message);
    }
}

module.exports = DatabaseError;
