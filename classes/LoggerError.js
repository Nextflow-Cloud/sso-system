export default class LoggerError extends Error {
    constructor(message) {
        super(message);
        this.name = 'LoggerError';
    }
}
