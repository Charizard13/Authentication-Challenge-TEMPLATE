const ACCESS_TOKEN_SECRET = "123456";
const REFRESH_TOKEN_SECRET = "1234567";
const express = require("express");
const app = express();
app.use(express.json());
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Users = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$ZkwWGWl2E53SI3CnxEbp7ubM79oGR3wUa.Ijt2F7hHOMqLdVA.kgG",
    isAdmin: true,
  },
  {
    email: "tal@gmail.com",
    name: "tal",
    password: "$2a$10$6smJyLzf5S5JpwIRId2XEuNUO.8Iiw4ub2aFtcZdjB.ecycqss9aW",
    isAdmin: false,
  },
];

const Information = [
  { name: "tal", info: "success" },
  { name: "admin", info: "success" },
];

let REFRESH_TOKENS = [];

let optionsMethod = [
  {
    method: "post",
    path: "/users/register",
    description: "Register, required: email, user, password",
    example: { email: "user@email.com", name: "user", password: "password" },
  },
  {
    method: "post",
    path: "/users/login",
    description: "Login, required: valid email and password",
    example: { email: "user@email.com", password: "password" },
  },
  {
    method: "post",
    path: "/users/token",
    description: "Renew access token, required: valid refresh token",
    example: { token: "*Refresh Token*" },
  },
  {
    method: "post",
    path: "/users/tokenValidate",
    description: "Access Token Validation, required: valid access token",
    example: { authorization: "Bearer *Access Token*" },
  },
  {
    method: "get",
    path: "/api/v1/information",
    description: "Access user's information, required: valid access token",
    example: { authorization: "Bearer *Access Token*" },
  },
  {
    method: "post",
    path: "/users/logout",
    description: "Logout, required: access token",
    example: { token: "*Refresh Token*" },
  },
  {
    method: "get",
    path: "/users/all",
    description: "Get users DB, required: Valid access token of admin user",
    example: { authorization: "Bearer *Access Token*" },
  },
];

app.post("/users/register", async (req, res) => {
  const emailExist = Users.find((user) => user.email === req.body.email);
  if (emailExist) return res.status(409).send("user already exists");

  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(req.body.password, salt);

  const user = {
    name: req.body.name,
    email: req.body.email,
    password: hashPassword,
    isAdmin: false,
  };

  Users.push(user);
  Information.push({ user: user.name, info: `${user.name} info` });
  res.status(201).send({ message: "Register Success" });
});

app.post("/users/login", async (req, res) => {
  const user = Users.find((user) => user.email === req.body.email);
  if (!user) return res.status(404).send("cannot find user");
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(403).send("User or Password incorrect");
  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET);
  REFRESH_TOKENS.push(refreshToken);
  res
    .status(200)
    .send({
      accessToken,
      refreshToken,
      userName: user.name,
      isAdmin: user.isAdmin,
    });
});

function generateAccessToken(user) {
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "30s" });
}

app.post("/users/tokenValidate", authenticateToken, (req, res) => {
  res.json({ valid: true });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access Token Required" });
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid Access Token" });
    req.user = user;
    next();
  });
}

app.get("/api/v1/information", authenticateToken, (req, res) => {
    if(req.user.isAdmin) return res.json(Information);
  res.json(Information.filter((info) => info.user === req.user.name));
});

app.post("/users/token", async (req, res) => {
  const token = req.body.token;
  if (!token) return res.status(401).send("Refresh Token Required");
  if (!REFRESH_TOKENS.includes(token))
    return res.status(403).send("Invalid Refresh Token");
  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid Refresh Token");
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.post("/users/logout", async (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).send("Refresh Token Required");
  REFRESH_TOKENS = REFRESH_TOKENS.filter((token) => token !== refreshToken);
  if (REFRESH_TOKENS)
    return res.status(200).json({message: "User Logged Out Successfully"});
  res.status(403).send("Invalid Refresh Token");
});

app.get("/api/v1/users", authenticateToken, (req, res) => {
    if (!req.user.isAdmin)
      return res.status(403).send("Invalid Refresh Token");
    res.json(Users);
});

app.options("/", (req, res) => {
  let RestOptions;
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    RestOptions = optionsMethod.slice(0, 2);
    res.json(RestOptions);
  }
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      RestOptions = optionsMethod.slice(0, 3);
      res.json(RestOptions);
    } else req.user = user;
  });
  if (req.user.isAdmin) res.json(optionsMethod);
  RestOptions = optionsMethod.slice(0, 6);
  res.json(RestOptions);
});
const unknownEndpointHandler = (req, res) => {
  res.status(404).send({ error: "unknown endpoint" });
};
app.use(unknownEndpointHandler);
const errorHandler = (err, req, res, next) => {
  console.error(err.message);
  next(err);
};
app.use(errorHandler);

module.exports = app;
