const https = require("https");
const selfsigned = require("selfsigned");
const fs = require("fs");
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const dotenv = require("dotenv");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/auth");
const session = require("express-session");
const app = express();
require("./config/passport");
dotenv.config();

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
    process.exit(1);
  });

app.use(express.json());

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // En production, utiliser cookies sécurisés
      httpOnly: true, // empêche l'accès aux cookies via JavaScript
      sameSite: "Strict", // empêche les attaques CSRF
      maxAge: 24 * 60 * 60 * 1000, // expiration après 24 heures
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.send("Hello, secure world!");
});

app.use("/auth", authRoutes);

const options = {
  key: fs.readFileSync("certs/localhost-key.pem"),
  cert: fs.readFileSync("certs/localhost.pem"),
};
const attrs = [{ name: "commonName", value: "localhost" }];
const cert = selfsigned.generate(attrs, options);

fs.writeFileSync("certs/server.crt", cert.cert);
fs.writeFileSync("certs/server.key", cert.private);

https.createServer(options, app).listen(3000, () => {
  console.log("Server is running on https://localhost:3000");
});
