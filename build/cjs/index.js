"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.simpleCsrf = void 0;
const csrf_1 = __importDefault(require("csrf"));
const csrf = new csrf_1.default();
const FORBIDDEN = 403;
function simpleCsrf(options) {
    const { cookieOptions, ignoreMethods = ["GET", "HEAD", "OPTIONS"], cookieName = "csrf", jsonError = { success: false }, } = options;
    const ignoreMethod = Array.from(new Set(ignoreMethods));
    if (!Array.isArray(ignoreMethod))
        throw new TypeError("ignoreMethods option must be an array");
    if (typeof cookieName !== "string" || cookieName.length === 0)
        throw new TypeError("cookieName is not valid, should be a non-empty string");
    return function middleware(req, res, next) {
        var _a, _b, _c;
        let csrfSecret = (_b = (_a = req.session.csrf) === null || _a === void 0 ? void 0 : _a.secret) !== null && _b !== void 0 ? _b : "";
        if (csrfSecret.length === 0)
            newCsrf(req, res, cookieName, cookieOptions);
        if (ignoreMethod.includes(req.method)) {
            return next();
        }
        const csrfToken = (_c = req.cookies[cookieName]) !== null && _c !== void 0 ? _c : "";
        if (csrfToken.length === 0)
            return res.status(FORBIDDEN).json(jsonError);
        if (csrfSecret.length === 0)
            return res.status(FORBIDDEN).json(jsonError);
        const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
        if (!isCsrfValid)
            return res.status(FORBIDDEN).json(jsonError);
        newCsrf(req, res, cookieName, cookieOptions);
        next();
    };
}
exports.simpleCsrf = simpleCsrf;
function newCsrf(req, res, cookieName, cookieOptions) {
    const secret = csrf.secretSync();
    const token = csrf.create(secret);
    req.session.csrf = { secret };
    res.cookie(cookieName, token, cookieOptions);
}
//# sourceMappingURL=index.js.map