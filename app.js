const express = require("express");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { UserModel } = require("./db");

require("dotenv").config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
app.use(express.json());

mongoose.connect(process.env.MONGODB_URL);

function auth(req, res, next) {
  const token = req.headers.token;

  const response = jwt.verify(token, JWT_SECRET);

  if (response) {
    req.id = response.id;
    next();
  } else {
    res.status(403).json({
      message: "Incorrect creds",
    });
  }
}

app.post("/signup", async function (req, res) {
  const password = req.body.password;
  const username = req.body.username;

  const hashedPassword = await bcrypt.hash(password, 10);

  await UserModel.create({
    password: hashedPassword,
    username: username,
  });

  res.json({
    message: "You are signed up",
  });
});

app.post("/signin", async function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  const response = await UserModel.findOne({
    username: username,
  });

  const passwordMatch = await bcrypt.compare(password, response.password);

  if (response && passwordMatch) {
    const token = jwt.sign(
      {
        id: response._id.toString(),
      },
      JWT_SECRET
    );

    res.json({
      token,
    });
  } else {
    res.status(403).json({
      message: "Incorrect creds",
    });
  }
});

app.get("/me", auth, async function (req, res) {
  const _id = req._id;
  const user = await UserModel.findById(req.id);
  const username = user.username;
  res.json({ username: username });
});

app.get("/generate-qr", async (req, res) => {
  const url =  req.query.url;

  if (!url) {
    return res.status(400).json({ message: "URL is required" });
  }

  try {
    const qr = await QRCode.toDataURL(url); // generates base64 image
    res.json({ qr });
  } catch (err) {
    res.status(500).json({ message: "Failed to generate QR", error: err });
  }
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.get("/index2", (req, res) => {
  res.sendFile(__dirname + "/public/index2.html");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
