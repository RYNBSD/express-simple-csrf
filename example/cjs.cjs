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
    ignorePaths: ["/ignore"],
    debug: true,
  })
);

app.get("/", (req, res) => {
  res.send("Unprotected");
});

app.post("/ignore", (req, res) => {
  res.send("Unprotected");
});

app.post("/", (req, res) => {
  res.send("Protected");
});

app.put("/", (req, res) => {
  res.send("Protected");
});

app.listen(3000, () => {
  console.log("start");
});
