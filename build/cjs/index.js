"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.simpleCsrf = void 0;
const csrf_1 = __importDefault(require("csrf"));
const http_status_codes_1 = require("http-status-codes");
// Creating a new instance of CSRF
const csrf = new csrf_1.default();
// CSRF middleware function
function simpleCsrf(options) {
    // Destructuring options object
    const { cookieOptions, // Options for CSRF cookie
    ignoreMethods = ["GET", "HEAD", "OPTIONS"], // HTTP methods to ignore CSRF check
    cookieName = "csrf", // Name of the CSRF cookie
     } = options;
    // Convert ignoreMethods to an array and ensure its validity
    const ignoreMethod = Array.from(new Set(ignoreMethods));
    // Validate ignoreMethod
    if (!Array.isArray(ignoreMethod))
        throw new TypeError("ignoreMethods option must be an array");
    // Validate cookieName
    if (typeof cookieName !== "string" || cookieName.length === 0)
        throw new TypeError("cookieName is not valid, should be a non-empty string");
    // CSRF middleware function
    return function middleware(req, res, next) {
        var _a, _b, _c;
        // Check if CSRF token exists in session
        let csrfSecret = (_b = (_a = req.session.csrf) === null || _a === void 0 ? void 0 : _a.secret) !== null && _b !== void 0 ? _b : "";
        // If CSRF token does not exist, create a new one
        if (csrfSecret.length === 0)
            newCsrf(req, res, cookieName, cookieOptions); // Generate new CSRF token
        // Check if HTTP method is ignored for CSRF check
        if (ignoreMethod.includes(req.method)) {
            return next(); // Proceed to next middleware
        }
        // HTTP method not ignored, CSRF check required //
        // Retrieve CSRF token from cookies
        const csrfToken = (_c = req.cookies[cookieName]) !== null && _c !== void 0 ? _c : "";
        if (csrfToken.length === 0)
            return res.sendStatus(http_status_codes_1.StatusCodes.FORBIDDEN);
        // Check if CSRF secret exists
        if (csrfSecret.length === 0)
            return res.sendStatus(http_status_codes_1.StatusCodes.FORBIDDEN);
        // Verify CSRF token
        const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
        if (!isCsrfValid)
            return res.sendStatus(http_status_codes_1.StatusCodes.FORBIDDEN);
        newCsrf(req, res, cookieName, cookieOptions);
        next(); // Proceed to next middleware
    };
}
exports.simpleCsrf = simpleCsrf;
// Function to generate a new CSRF token
function newCsrf(req, res, cookieName, cookieOptions) {
    const secret = csrf.secretSync(); // Generate CSRF secret
    const token = csrf.create(secret);
    req.session.csrf = { secret }; // Store CSRF secret in session
    res.cookie(cookieName, token, cookieOptions); // Set CSRF token in cookie
}
//# sourceMappingURL=index.js.map