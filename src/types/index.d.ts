import type { SessionData } from "express-session"

interface Csrf {
  csrf: {
    secret: string
  }
}

declare module "express-session" {
  interface SessionData extends Csrf {}
}