import Csrf from "csrf";
const csrf = new Csrf();
const FORBIDDEN = 403;
export function simpleCsrf(options) {
    const { cookieOptions, ignoreMethods = ["GET", "HEAD", "OPTIONS"], cookieName = "csrf", jsonError = { success: false }, debug = false, } = options;
    const ignoreMethod = Array.from(new Set(ignoreMethods));
    if (!Array.isArray(ignoreMethod))
        throw new TypeError("ignoreMethods option must be an array");
    if (typeof cookieName !== "string" || cookieName.length === 0)
        throw new TypeError("cookieName is not valid, should be a non-empty string");
    return function middleware(req, res, next) {
        const csrfSecret = req.session.csrf?.secret ?? "";
        if (csrfSecret.length === 0)
            newCsrf(req, res, cookieName, cookieOptions);
        if (ignoreMethod.includes(req.method)) {
            return next();
        }
        const csrfToken = req.cookies[cookieName] ?? "";
        if (debug) {
            console.debug(`Secret: ${csrfSecret}`);
            console.debug(`Token: ${csrfToken}`);
        }
        if (csrfToken.length === 0)
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf token",
                ...jsonError,
            });
        if (csrfSecret.length === 0)
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf secret",
                ...jsonError,
            });
        const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
        if (!isCsrfValid)
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf",
                ...jsonError,
            });
        newCsrf(req, res, cookieName, cookieOptions);
        next();
    };
}
function newCsrf(req, res, cookieName, cookieOptions) {
    const secret = csrf.secretSync();
    const token = csrf.create(secret);
    req.session.csrf = { secret };
    res.cookie(cookieName, token, cookieOptions);
}
//# sourceMappingURL=index.js.map