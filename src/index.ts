import type { Request, Response, NextFunction, CookieOptions } from "express";
import createError from "http-errors";
import Token from "csrf";
import { StatusCodes } from "http-status-codes";

export default function csrf(options: Options) {
  const {
    cookieOptions,
    ignoreMethods = ["GET", "HEAD", "OPTIONS"],
    cookieName = "csrf",
  } = options;

  const ignoreMethod = Array.from(new Set(ignoreMethods));

  if (!Array.isArray(ignoreMethod))
    throw new TypeError("ignoreMethod option must be an array");

  return function (req: Request, res: Response, next: NextFunction) {
    // Check if csrf token exists
    let csrfSecret = req.session.csrf?.secret ?? "";

    // If does not exists create new one
    if (csrfSecret.length === 0) {
      const token = newCsrf(req);
      res.cookie(cookieName, token, cookieOptions);
      req.cookies[cookieName] = token;
    }

    // Check if method is ignored
    if (ignoreMethod.includes(req.method as Methods)) {
      return next();
    }

    // method not ignored ⬇️ (check csrf) //

    // get csrf token from cookies
    const csrfToken = req.cookies[cookieName] ?? "";
    if (csrfToken.length === 0)
      return next(
        createError(StatusCodes.FORBIDDEN, "Csrf token not provided")
      );

    if (csrfSecret.length === 0)
      next(createError(StatusCodes.FORBIDDEN, "Expired csrf token"));

    const isCsrfValid = new Token().verify(csrfSecret, csrfToken);
    if (!isCsrfValid)
      return next(createError(StatusCodes.FORBIDDEN, "Invalid csrf token"));

    next();
  };
}

function newCsrf(req: Request) {
  const token = new Token();
  const secret = token.secretSync();
  req.session.csrf = { secret };
  return token;
}

type Methods = "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS";

type Options = {
  cookieOptions: CookieOptions;
  ignoreMethods?: Methods[];
  cookieName?: string;
};
