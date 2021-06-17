const express = require("express");
const bcrypt = require("bcrypt"); // bcrypt is used to hash password before saving it to database
const fs = require("fs"); // fs is node's inbuilt file system module used to manage files
const utils = require("../utils");

const usersDb = require("../database/db.json"); // import existing data from db.json file

const router = express.Router(); // we create a new router using express's inbuilt Router method

// create a new user with the give email, name, and hashed password
router.post("/sign-up", async (req, res) => {
  // get the name, email and password from the body
  const { name, email, password } = req.body;

  // make sure there is no existing user with this email
  const existingUser = usersDb.find((user) => user.email == email);
  if (existingUser) {
    // if there is, return an error
    res.status(400).send({ error: "User already exists!" });
    return;
  }

  // calculate the hash for this the given password
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  // create a new user object with the email, name and hashed password
  const user = {
    id: usersDb.length,
    name: name,
    email: email,
    password: hashedPassword,
  };

  // push that user object into the userdb array
  usersDb.push(user);

  // save that userdb array to the filesystem as db.json
  fs.writeFileSync("./database/db.json", JSON.stringify(usersDb));

  // generate a JWT for this user's ID
  const jwt = utils.generateJWT(user.id);

  // return the JWT so they can start making authenticated requests
  res.status(201).send({ jwt: jwt });
});

router.post("/sign-in", function (req, res) {
  // get email and password from body
  const { email, password } = req.body;

  // find user with that email address
  const user = usersDb.find((user) => user.email == email);
  if (!user) {
    // if none exists return error 401 - unauthorized
    res.status(401).send({ error: "unauthorized" });
    return;
  }

  // get the hashedPassword from the user object and compare it to the password from body
  const hashedPassword = user.password;
  const isValid = bcrypt.compareSync(password, hashedPassword);

  if (!isValid) {
    // if they dont match return error 401 - unauthorized
    res.status(401).send({ error: "unauthorized" });
    return;
  }

  // generate a JWT for this user's ID
  const jwt = utils.generateJWT(user.id);

  // return the JWT so they can start making authenticated requests
  res.status(200).send({ jwt: jwt });
});

// only allow access if the request contained a header with a valid json webtoken
function authMiddleware(request, response, next) {
  // get jwt from headers
  const jwt = request.header("authorization");
  // validate JWT
  const userId = utils.decodeJWT(jwt);
  if (!userId) {
    //   if invalid, return status 401 - unauthorized
    response.status(401).send({ error: "unauthorized" });
    return;
  }
  request.userId = userId;
  next();
}

// only allow access if the request contained a header with a valid json webtoken
// return the users id and email
router.get("/auth", authMiddleware, function (req, response) {
  // find user with the ID that's in the JWT
  const user = usersDb.find((user) => user.id == req.userId);

  if (!user) {
    response.status(404).send({ error: "not found" });
    return;
  }

  // return a json object with that id and the user's email
  response.send({
    id: user.id,
    email: user.email,
  });
});

module.exports = router; // we need to export this router to implement it inside our server.js file
