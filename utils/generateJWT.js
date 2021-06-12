const jsonwebtoken = require("jsonwebtoken");
require("dotenv").config(); // here we use dotenv module which we installed in the begining to access environment variables from .env file

// take an id, calculate and return a signed JWT
function generateJWT(userId) {
  const secret = process.env.JWT_SECRET;
  const jwt = jsonwebtoken.sign({ id: userId }, secret);
  return jwt;
}

module.exports = {
  generateJWT: generateJWT,
};
