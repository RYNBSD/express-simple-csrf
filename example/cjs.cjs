const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { simpleCsrf } = require("../build/cjs/index.js");

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
  simpleCsrf({
    cookieOptions /* required */: { path: "/", maxAge: 1000 * 60 * 15 },
    ignoreMethods /* not required */: ["GET", "HEAD", "OPTIONS"], // default
    cookieName /* not required */: "csrf", // default
    jsonError /* not required */: { success: false }, // default
    debug /* not required */: false, //default
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

app.put("/", (req, res) => {
  console.log(req.session, req.cookies);
  res.send("Protected");
});

app.listen(3000, () => {
  console.log("start");
});
