const express = require("express");
const cors = require("cors");
const homeRoutes = require("./routes/homeRoutes");
const eventRoutes = require("./routes/eventRoutes");

require("dotenv").config();
require("./lib/firebase"); 

const authRoutes = require("./routes/authRoutes");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.use("/auth", authRoutes);
app.use("/homepage", homeRoutes);
app.use("/events", eventRoutes);

module.exports = app;