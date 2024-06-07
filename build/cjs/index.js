"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.simpleCsrf = exports.X_NO_CSRF = void 0;
const csrf_1 = __importDefault(require("csrf"));
exports.X_NO_CSRF = "X-No-Csrf";
const csrf = new csrf_1.default();
const FORBIDDEN = 403;
function simpleCsrf(options) {
    const { cookieOptions, ignoreMethods = ["GET", "HEAD", "OPTIONS", "PATCH"], ignorePaths = [], cookieName = "csrf", jsonError = { success: false }, debug = false, xNoCsrf = exports.X_NO_CSRF.toLowerCase(), } = options;
    if (!Array.isArray(ignoreMethods))
        throw new TypeError("ignoreMethods option must be an array");
    const ignoreMethod = Array.from(new Set(ignoreMethods));
    if (!Array.isArray(ignorePaths))
        throw new TypeError("ignorePaths option must be an array");
    const ignorePath = Array.from(new Set(ignorePaths));
    if (typeof cookieName !== "string" || cookieName.length === 0)
        throw new TypeError("cookieName is not valid, should be a non-empty string");
    if (typeof xNoCsrf !== "string")
        throw new TypeError("xNoCsrf (header property) must be a string");
    return function middleware(req, res, next) {
        var _a, _b, _c, _d;
        const csrfSecret = (_b = (_a = req.session.csrf) === null || _a === void 0 ? void 0 : _a.secret) !== null && _b !== void 0 ? _b : "";
        const csrfToken = (_c = req.cookies[cookieName]) !== null && _c !== void 0 ? _c : "";
        if (debug)
            debugFn(csrfSecret, csrfToken);
        if (csrfSecret.length === 0) {
            const { secret: newSecret, token: newToken } = newCsrf(req, res, cookieName, cookieOptions);
            if (debug)
                debugFn(newSecret, newToken, { isIn: false });
            return next();
        }
        if (xNoCsrf.length > 0) {
            const noCsrf = (_d = req.headers[xNoCsrf]) !== null && _d !== void 0 ? _d : "";
            if (Boolean(Array.isArray(noCsrf) ? noCsrf.join() : noCsrf)) {
                if (debug)
                    debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
                return next();
            }
        }
        if (ignoreMethod.includes(req.method)) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return next();
        }
        if (ignorePath.includes(req.path)) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return next();
        }
        if (csrfToken.length === 0) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json(Object.assign({ message: "Invalid csrf token" }, jsonError));
        }
        if (csrfSecret.length === 0) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json(Object.assign({ message: "Invalid csrf secret" }, jsonError));
        }
        const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
        if (!isCsrfValid) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json(Object.assign({ message: "Invalid csrf" }, jsonError));
        }
        const { secret: newSecret, token: newToken } = newCsrf(req, res, cookieName, cookieOptions);
        if (debug)
            debugFn(newSecret, newToken, { isIn: false });
        next();
    };
}
exports.simpleCsrf = simpleCsrf;
function newCsrf(req, res, cookieName, cookieOptions) {
    const secret = csrf.secretSync();
    const token = csrf.create(secret);
    req.session.csrf = { secret };
    res.cookie(cookieName, token, cookieOptions);
    return { secret, token };
}
function debugFn(secret, token, { isIn = true, isChanged = true } = {}) {
    console.debug(`${isIn ? "In" : "Out"}:`);
    console.debug(`Secret: ${secret || "Empty"}`);
    console.debug(`Token: ${token || "Empty"}`);
    if (!isChanged)
        console.debug("Csrf did not changed");
}
//# sourceMappingURL=index.js.map