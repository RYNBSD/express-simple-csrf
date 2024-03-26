import type { Request, Response, NextFunction, CookieOptions } from "express";
export default function csrf(options: Options): (req: Request, res: Response, next: NextFunction) => void;
type Methods = "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS";
type Options = {
    cookieOptions: CookieOptions;
    ignoreMethods?: Methods[];
    cookieName?: string;
};
export {};
//# sourceMappingURL=index.d.ts.map