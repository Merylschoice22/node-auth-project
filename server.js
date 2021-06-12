const express = require("express");
const cors = require("cors");
const userRouter = require("./routes/user");

// initializing express application
const app = express();

// parse requests of content-type - application/json
app.use(express.json());

const corsOptions = {
  origin: "http://localhost:3000",
};

app.use(cors(corsOptions)); // enable CORS
app.use("/", userRouter);

// simple route
app.get("/", (req, res) => {
  res.send({ message: "Welcome to MigraCode Auth application." });
});

// set port, listen for requests
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
