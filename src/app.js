const express = require("express");
const cors = require("cors");
const homeRoutes = require("./routes/homeRoutes");
const eventRoutes = require("./routes/eventRoutes");
const taskRoutes = require("./routes/taskRoutes");
const authRoutes = require("./routes/authRoutes");
const messageRoutes = require("./routes/messageRoutes");
const postRoutes = require("./routes/postRoutes");


require("dotenv").config();
require("./lib/firebase"); 



const app = express();

app.use(cors());
app.use(express.json());
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:5173"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.use("/auth", authRoutes);
app.use("/homepage", homeRoutes);
app.use("/events", eventRoutes);
app.use("/tasks", taskRoutes);
app.use("/messages", messageRoutes);
app.use("/posts", postRoutes);
module.exports = app;