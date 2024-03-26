// Importing necessary types and modules
import type { Request, Response, NextFunction, CookieOptions } from "express";
import createError from "http-errors";
import Csrf from "csrf";
import { StatusCodes } from "http-status-codes";

// Creating a new instance of CSRF
const csrf = new Csrf();

// CSRF middleware function
export default function (options: Options) {
  // Destructuring options object
  const {
    cookieOptions, // Options for CSRF cookie
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
    throw new TypeError(
      "cookieName is not valid, should be a non-empty string"
    );

  // CSRF middleware function
  return function middleware(req: Request, res: Response, next: NextFunction) {
    // Check if CSRF token exists in session
    let csrfSecret = req.session.csrf?.secret ?? "";

    // If CSRF token does not exist, create a new one
    if (csrfSecret.length === 0) newCsrf(req, res, cookieName, cookieOptions); // Generate new CSRF token

    csrfSecret = req.session.csrf?.secret ?? "";

    // Check if HTTP method is ignored for CSRF check
    if (ignoreMethod.includes(req.method as Methods)) {
      return next(); // Proceed to next middleware
    }

    // HTTP method not ignored, CSRF check required //

    // Retrieve CSRF token from cookies
    const csrfToken = req.cookies[cookieName] ?? "";
    if (csrfToken.length === 0)
      return next(
        createError(StatusCodes.FORBIDDEN, "Csrf token not provided")
      );

    // Check if CSRF secret exists
    if (csrfSecret.length === 0)
      return next(createError(StatusCodes.FORBIDDEN, "Expired csrf token"));

    // Verify CSRF token
    const isCsrfValid = csrf.verify(csrfSecret, csrfToken);
    if (!isCsrfValid)
      return next(createError(StatusCodes.FORBIDDEN, "Invalid csrf token"));

    newCsrf(req, res, cookieName, cookieOptions);
    next(); // Proceed to next middleware
  };
}

// Function to generate a new CSRF token
function newCsrf(
  req: Request,
  res: Response,
  cookieName: string,
  cookieOptions: CookieOptions
) {
  const secret = csrf.secretSync(); // Generate CSRF secret
  const token = csrf.create(secret);
  req.session.csrf = { secret }; // Store CSRF secret in session
  res.cookie(cookieName, token, cookieOptions); // Set CSRF token in cookie
  req.cookies[cookieName] = token; // Store CSRF token in request object
}

// Supported HTTP methods
type Methods = "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS";

// Options for CSRF middleware
type Options = {
  cookieOptions: CookieOptions; // Options for CSRF cookie
  ignoreMethods?: Methods[]; // HTTP methods to ignore CSRF check
  cookieName?: string; // Name of the CSRF cookie
};
