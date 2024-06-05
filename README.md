An unofficial csrf protection for express.js<br>
**Simple** but **strong**<br>
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
const { simpleCsrf } = require("express-simple-csrf");
```

## Esm

```js
import express from "express";
import cookieParser from "cookie-parser";
import session from "express-session";
import { simpleCsrf } from "express-simple-csrf";
```

## Usage

```js
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
/*
  That simple
  hover on the function to see full options and description
*/
app.use(
  simpleCsrf({
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

# Features
Full customizable, you can customize how to handle each request, by add csrf disable header, ignored methods or paths and the middleware is very simple to use

# How it work?

![Algorithm](/assets/images/algorithm.png)
