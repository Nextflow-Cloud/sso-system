export default class ErrorError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ErrorHandlerError';
    }
}