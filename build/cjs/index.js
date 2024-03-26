"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var http_errors_1 = __importDefault(require("http-errors"));
var csrf_1 = __importDefault(require("csrf"));
var http_status_codes_1 = require("http-status-codes");
// CSRF middleware function
function csrf(options) {
    // Destructuring options object
    var cookieOptions = options.cookieOptions, // Options for CSRF cookie
    _a = options.ignoreMethods, // Options for CSRF cookie
    ignoreMethods = _a === void 0 ? ["GET", "HEAD", "OPTIONS"] : _a, // HTTP methods to ignore CSRF check
    _b = options.cookieName, // HTTP methods to ignore CSRF check
    cookieName = _b === void 0 ? "csrf" : _b;
    // Convert ignoreMethods to an array and ensure its validity
    var ignoreMethod = Array.from(new Set(ignoreMethods));
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
        var csrfSecret = (_b = (_a = req.session.csrf) === null || _a === void 0 ? void 0 : _a.secret) !== null && _b !== void 0 ? _b : "";
        // If CSRF token does not exist, create a new one
        if (csrfSecret.length === 0)
            newCsrf(req, res, cookieName, cookieOptions); // Generate new CSRF token
        // Check if HTTP method is ignored for CSRF check
        if (ignoreMethod.includes(req.method)) {
            return next(); // Proceed to next middleware
        }
        // HTTP method not ignored, CSRF check required //
        // Retrieve CSRF token from cookies
        var csrfToken = (_c = req.cookies[cookieName]) !== null && _c !== void 0 ? _c : "";
        if (csrfToken.length === 0)
            return next((0, http_errors_1.default)(http_status_codes_1.StatusCodes.FORBIDDEN, "Csrf token not provided"));
        // Check if CSRF secret exists
        if (csrfSecret.length === 0)
            next((0, http_errors_1.default)(http_status_codes_1.StatusCodes.FORBIDDEN, "Expired csrf token"));
        // Verify CSRF token
        var isCsrfValid = new csrf_1.default().verify(csrfSecret, csrfToken);
        if (!isCsrfValid)
            return next((0, http_errors_1.default)(http_status_codes_1.StatusCodes.FORBIDDEN, "Invalid csrf token"));
        newCsrf(req, res, cookieName, cookieOptions);
        next(); // Proceed to next middleware
    };
}
exports.default = csrf;
// Function to generate a new CSRF token
function newCsrf(req, res, cookieName, cookieOptions) {
    var token = new csrf_1.default(); // Create new CSRF token
    var secret = token.secretSync(); // Generate CSRF secret
    req.session.csrf = { secret: secret }; // Store CSRF secret in session
    res.cookie(cookieName, token, cookieOptions); // Set CSRF token in cookie
    req.cookies[cookieName] = token; // Store CSRF token in request object
}
//# sourceMappingURL=index.js.map