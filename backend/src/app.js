const express = require("express");
const cors = require("cors");

const userRoutes = require("./routes/users.routes");

const app = express();

app.use(cors());
app.use(express.json());

// Rutas
app.use("/users", userRoutes);

// Ruta base
app.get("/", (req, res) => {
  res.send("✅ Backend TasksCompleted funcionando");
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date(),
  });
});

module.exports = app;
