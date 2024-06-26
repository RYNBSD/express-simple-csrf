import type { Request, Response, NextFunction, CookieOptions } from "express";
export declare const X_NO_CSRF = "X-No-Csrf";
export declare function simpleCsrf(options: Options): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
type Methods = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
type Options = {
    cookieOptions: CookieOptions;
    ignoreMethods?: Methods[];
    ignorePaths?: string[];
    cookieName?: string;
    jsonError?: Record<string, any>;
    debug?: boolean;
    xNoCsrf?: string;
};
export {};
//# sourceMappingURL=index.d.ts.map