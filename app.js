"use strict";

const express = require("express");
const app = express();

const path = require("path");
const exphbs = require("express-handlebars");
const helmet = require("helmet");
const session = require("express-session");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const escapeHtml = require("escape-html");

app.disable("x-powered-by");

app.use(
  "/static",
  express.static(path.join(__dirname, "static"), {
    fallthrough: false,
    index: false,
    maxAge: "1h",
  })
);

app.use(bodyParser.urlencoded({ extended: false, limit: "10kb" }));
app.use(bodyParser.json({ limit: "10kb" }));

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "frame-ancestors": ["'none'"],
      },
    },
    frameguard: { action: "deny" },
  })
);

app.use(cookieParser());

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "CHANGE_ME_IN_PROD",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60000 * 60 * 24,
    },
  })
);

const csrfProtection = csrf({ cookie: true });

app.engine(
  ".html",
  exphbs.engine({
    extname: ".html",
    partialsDir: path.join(__dirname, "views"),
    defaultLayout: "head",
  })
);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", ".html");

let global_var =
  "This is a greeting to all users that view this page! Change it in the box below.";

function safeStr(v, maxLen = 2000) {
  if (v === undefined || v === null) return "";
  const s = String(v);
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function safeEscaped(v, maxLen = 2000) {
  return escapeHtml(safeStr(v, maxLen));
}

function isValidUsername(u) {
  return /^[a-zA-Z0-9._-]{1,32}$/.test(u);
}

function isValidViewName(v) {
  return /^[a-zA-Z0-9._-]+\.html$/.test(v);
}

app.get("/", (req, res) => res.render("main", {}));

app.get("/reflected_xss", (req, res) => {
  return res.render("reflected", { payload: safeEscaped(req.query.foobar) });
});

app.get("/reflected_xss_2", (req, res) => {
  return res.render("reflected1", { payload: safeEscaped(req.query.foo) });
});

app.get("/reflected_xss_3", (req, res) => {
  return res.render("reflected2", { payload: safeEscaped(req.query.foo) });
});

app.get("/stored_xss", csrfProtection, (req, res) => {
  return res.render("stored", {
    payload: safeEscaped(global_var, 5000),
    csrfToken: req.csrfToken(),
  });
});

app.post("/stored_xss", csrfProtection, (req, res) => {
  global_var = safeStr(req.body.stored_payload, 5000);
  return res.redirect("/stored_xss");
});

app.get("/csrf", csrfProtection, (req, res) => {
  if (typeof req.session.account_number === "undefined") {
    req.session.account_number = "1234567";
  }
  return res.render("csrf", {
    account_number: safeEscaped(req.session.account_number, 32),
    csrfToken: req.csrfToken(),
  });
});

app.post("/csrf", csrfProtection, (req, res) => {
  const acct = safeStr(req.body.account_number, 32);

  if (!/^\d{7,20}$/.test(acct)) {
    return res.status(400).send("Invalid account_number");
  }

  req.session.account_number = acct;
  return res.redirect("/csrf");
});

app.get("/views/:view", (req, res) => {
  const view = safeStr(req.params.view, 128);

  if (!isValidViewName(view)) {
    return res.status(400).send("Invalid view name");
  }

  const viewsRoot = path.join(__dirname, "views");
  return res.sendFile(view, { root: viewsRoot });
});

app.get("/private_pages/:id/document.html", (req, res) => {
  const id = safeStr(req.params.id, 32);

  if (!/^\d+$/.test(id)) {
    return res.status(400).render("idor_bad", { id: safeEscaped(id), notNum: true });
  }

  if (!req.session.allowedDocs) req.session.allowedDocs = ["123"];

  if (req.session.allowedDocs.includes(id)) {
    return res.render("idor");
  }

  return res.status(403).render("idor_bad", { id: safeEscaped(id) });
});

app.get("/rce", (req, res) => res.render("rce"));

app.get("/fuzzing/:fuzz", (req, res) => {
  const fuzz = safeStr(req.params.fuzz, 256);
  return res.render("fuzz", { fuzz: safeEscaped(fuzz, 256) });
});

app.get("/ban/user/:user", (req, res) => {
  const user = safeStr(req.params.user, 64);

  if (!isValidUsername(user)) {
    return res.status(400).send("Invalid username");
  }

  return res.render("banned", { user: safeEscaped(user, 64) });
});

app.get("/auth_bypass", (req, res) => res.render("auth_bypass"));

app.get("/general", (req, res) => {
  return res.render("general", { payload: safeEscaped(req.query.foo) });
});

app.post("/csrf_protected_form", csrfProtection, (req, res) => {
  if (!req.body.recoveryemail) {
    return res.status(400).send("Missing recoveryemail");
  }

  const email = safeStr(req.body.recoveryemail, 254);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).send("Invalid email");
  }

  return res.status(200).send("Successfully Saved");
});

module.exports = app;
