const express = require("express");
const router = express.Router();
const prisma = require("../utils/prisma");
require("./routes/users.routes");


router.get("/", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Error obteniendo usuarios" });
  }
});

module.exports = router;
