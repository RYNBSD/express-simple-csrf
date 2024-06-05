import Csrf from "csrf";
export const X_NO_CSRF = "X-No-Csrf";
const csrf = new Csrf();
const FORBIDDEN = 403;
export function simpleCsrf(options) {
    const { cookieOptions, ignoreMethods = ["GET", "HEAD", "OPTIONS", "PATCH"], ignorePaths = [], cookieName = "csrf", jsonError = { success: false }, debug = false, xNoCsrf = X_NO_CSRF.toLowerCase(), } = options;
    const ignoreMethod = Array.from(new Set(ignoreMethods));
    if (!Array.isArray(ignoreMethod))
        throw new TypeError("ignoreMethods option must be an array");
    if (typeof cookieName !== "string" || cookieName.length === 0)
        throw new TypeError("cookieName is not valid, should be a non-empty string");
    if (typeof xNoCsrf !== "string")
        throw new TypeError("xNoCsrf (header property) must be a string");
    return function middleware(req, res, next) {
        const csrfSecret = req.session.csrf?.secret ?? "";
        const csrfToken = req.cookies[cookieName] ?? "";
        if (debug)
            debugFn(csrfSecret, csrfToken);
        if (csrfSecret.length === 0) {
            const { secret: newSecret, token: newToken } = newCsrf(req, res, cookieName, cookieOptions);
            if (debug)
                debugFn(newSecret, newToken, { isIn: false });
            return next();
        }
        if (xNoCsrf.length > 0) {
            const noCsrf = req.headers[xNoCsrf] ?? "";
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
        if (ignorePaths.includes(req.path)) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return next();
        }
        if (csrfToken.length === 0) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf token",
                ...jsonError,
            });
        }
        if (csrfSecret.length === 0) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf secret",
                ...jsonError,
            });
        }
        const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
        if (!isCsrfValid) {
            if (debug)
                debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
            return res.status(FORBIDDEN).json({
                message: "Invalid csrf",
                ...jsonError,
            });
        }
        const { secret: newSecret, token: newToken } = newCsrf(req, res, cookieName, cookieOptions);
        if (debug)
            debugFn(newSecret, newToken, { isIn: false });
        next();
    };
}
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