An unofficial csrf protection for express.js.<br>
You can use both **Esm** and **Cjs**

# Install

```bash
  npm i express-simple-csrf
  yarn add express-simple-csrf
  pnpm i express-simple-csrf
  bun add express-simple-csrf
```

# How to use ?

First you need to install **cookie-parser** and **express-session**

## Cjs

```js
const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { default: csrf } = require("../build/cjs/index.js");

const app = express();

app.use(cookieParser("secret"));
app.use(
  session({
    secret: "secret",
    saveUninitialized: false,
    resave: false,
    cookie: {
      path: "/",
      maxAge: 1000 * 60 * 15,
    },
  })
);
app.use(
  csrf({
    ignoreMethods /* not required */: ["GET", "HEAD", "OPTIONS"], // default
    cookieName /* not required */: "csrf", // default
    cookieOptions /* required */: { path: "/", maxAge: 1000 * 60 * 15 },
  })
);

app.get("/", (req, res) => {
  console.log(req.session, req.cookies);
  res.send("Unprotected");
});

app.post("/", (req, res) => {
  console.log(req.session, req.cookies);
  res.send("Protected");
});

app.listen(3000, () => {
  console.log("start");
});
```

## Esm

```js
import express from "express";
import cookieParser from "cookie-parser";
import session from "express-session";
import csrf from "../build/esm/index.js";

const app = express();

app.use(cookieParser("secret"));
app.use(
  session({
    secret: "secret",
    saveUninitialized: false,
    resave: false,
    cookie: {
      path: "/",
      maxAge: 1000 * 60 * 15,
    },
  })
);
app.use(
  csrf({
    ignoreMethods /* not required */: ["GET", "HEAD", "OPTIONS"], // default
    cookieName /* not required */: "csrf", // default
    cookieOptions /* required */: { path: "/", maxAge: 1000 * 60 * 15 },
  })
);

app.get("/", (req, res) => {
  console.log(req.session, req.cookies);
  res.send("Unprotected");
});

app.post("/", (req, res) => {
  console.log(req.session, req.cookies);
  res.send("Protected");
});

app.listen(3000, () => {
  console.log("start");
});
```
