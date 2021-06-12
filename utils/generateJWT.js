const jsonwebtoken = require("jsonwebtoken");
require("dotenv").config(); // here we use dotenv module which we installed in the begining to access environment variables from .env file

// take an id, calculate and return a signed JWT
function generateJWT(userId) {
  const secret = process.env.JWT_SECRET;
  const jwt = jsonwebtoken.sign({ id: userId }, secret, { expiresIn: "1h" });
  return jwt;
}

//take a JWT string, verify that the signature mathes (based on your secret)
//if it matches, return the userID, otherwise return false
const decodeJWT = (jwt) => {
  const secret = process.env.JWT_SECRET;
  try {
    const data = jsonwebtoken.verify(jwt, secret);
    return data.id;
  } catch (error) {
    return false;
  }
};

module.exports = {
  generateJWT: generateJWT,
  decodeJWT: decodeJWT,
};
