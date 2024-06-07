import type { Request, Response, NextFunction, CookieOptions } from "express";
import Csrf from "csrf";

export const X_NO_CSRF = "X-No-Csrf";

// Creating a new instance of CSRF
const csrf = new Csrf();
const FORBIDDEN = 403;

/**
 *
 * @param options - Options
 * @param options.cookieOptions - cookie options to store csrf token in client, required
 * @param options.ignoreMethods - Http methods that ignore csrf check, default: ["GET", "HEAD", "OPTIONS", "PATCH"]
 * @param options.ignorePaths - req paths that ignore csrf check, default: []
 * @param options.cookieName - token cookie name, default: csrf
 * @param options.jsonError - json response error, default: { success: false }
 * @param options.debug - debug mode, default: false
 * @param options.xNoCsrf - header option to disable csrf, default: x-no-csrf
 * @returns
 */
export function simpleCsrf(options: Options) {
  const {
    cookieOptions, // Options for CSRF cookie
    ignoreMethods = ["GET", "HEAD", "OPTIONS", "PATCH"], // HTTP methods to ignore CSRF check
    ignorePaths = [], // req paths that ignore csrf protection
    cookieName = "csrf", // Name of the CSRF cookie
    jsonError = { success: false },
    debug = false,
    xNoCsrf = X_NO_CSRF.toLowerCase(), // If length equal 0, don't skip csrf check
  } = options;

  // Validate ignoreMethods
  if (!Array.isArray(ignoreMethods))
    throw new TypeError("ignoreMethods option must be an array");

  // Convert ignoreMethods to an array and ensure its validity
  const ignoreMethod = Array.from(new Set(ignoreMethods));

  // Validate ignorePaths
  if (!Array.isArray(ignorePaths))
    throw new TypeError("ignorePaths option must be an array");

  const ignorePath = Array.from(new Set(ignorePaths));

  // Validate cookieName
  if (typeof cookieName !== "string" || cookieName.length === 0)
    throw new TypeError(
      "cookieName is not valid, should be a non-empty string"
    );

  if (typeof xNoCsrf !== "string")
    throw new TypeError("xNoCsrf (header property) must be a string");

  // CSRF middleware function
  return function middleware(req: Request, res: Response, next: NextFunction) {
    // Get csrf secret from the session
    const csrfSecret = req.session.csrf?.secret ?? "";

    // Get csrf token from the cookies
    const csrfToken = req.cookies[cookieName] ?? "";

    // Check if debug mode is true
    if (debug) debugFn(csrfSecret, csrfToken);

    // If CSRF secret is empty then create new csrf
    if (csrfSecret.length === 0) {
      const { secret: newSecret, token: newToken } = newCsrf(
        req,
        res,
        cookieName,
        cookieOptions
      );
      if (debug) debugFn(newSecret, newToken, { isIn: false });
      return next();
    }

    // check if xNoCsrf option is passed to enable skip option
    if (xNoCsrf.length > 0) {
      // Get x-no-csrf header to disable csrf if true
      const noCsrf = req.headers[xNoCsrf] ?? "";
      // If true, disable csrf protection for this request
      if (Boolean(Array.isArray(noCsrf) ? noCsrf.join() : noCsrf)) {
        if (debug)
          debugFn(csrfSecret, csrfToken, { isIn: false, isChanged: false });
        return next();
      }
    }

    // If req method is in ignore list then skip csrf check
    if (ignoreMethod.includes(req.method as Methods)) {
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

    // Generate and set a new CSRF token
    const { secret: newSecret, token: newToken } = newCsrf(
      req,
      res,
      cookieName,
      cookieOptions
    );
    if (debug) debugFn(newSecret, newToken, { isIn: false });
    next();
  };
}

// Function to generate a new CSRF token
function newCsrf(
  req: Request,
  res: Response,
  cookieName: string,
  cookieOptions: CookieOptions
) {
  const secret = csrf.secretSync();
  const token = csrf.create(secret);
  req.session.csrf = { secret };
  res.cookie(cookieName, token, cookieOptions);
  return { secret, token };
}

/**
 *
 * @param secret - Csrf secret
 * @param token - Csrf token
 * @param options - Debug options
 */
function debugFn(
  secret: string,
  token: string,
  { isIn = true, isChanged = true } = {}
) {
  console.debug(`${isIn ? "In" : "Out"}:`);
  console.debug(`Secret: ${secret || "Empty"}`);
  console.debug(`Token: ${token || "Empty"}`);
  if (!isChanged) console.debug("Csrf did not changed");
}

// Supported HTTP methods
type Methods = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

// Options for CSRF middleware
type Options = {
  cookieOptions: CookieOptions; // Options for CSRF cookie
  ignoreMethods?: Methods[]; // HTTP methods to ignore CSRF check
  ignorePaths?: string[]; // req paths to ignore CSRF check
  cookieName?: string; // Name of the CSRF cookie
  jsonError?: Record<string, any>; // json response on failure (invalid csrf)
  debug?: boolean; // debug mode
  xNoCsrf?: string; // csrf disable header
};
