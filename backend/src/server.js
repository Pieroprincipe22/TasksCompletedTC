require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// ---------- Rutas básicas ----------
app.get("/", (req, res) => {
  res.send("API corriendo ✅");
});

app.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, db: true });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: String(e?.message || e) });
  }
});

// ---------- USERS (básico) ----------
app.get("/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: "Error listando usuarios", detail: String(e?.message || e) });
  }
});

// OJO: Este endpoint crea usuario con password en texto plano.
// Úsalo solo para pruebas. En producción usar /auth/register.
app.post("/users", async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: "email, password y name son obligatorios" });
  }

  try {
    const user = await prisma.user.create({
      data: { email, password, name },
    });

    res.status(201).json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
    });
  } catch (e) {
    if (String(e).includes("Unique constraint")) {
      return res.status(409).json({ error: "Ese email ya existe" });
    }
    res.status(500).json({ error: "Error creando usuario", detail: String(e?.message || e) });
  }
});

// ---------- Auth middleware ----------
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Token requerido (Bearer)" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

// ---------- AUTH ----------
app.post("/auth/register", async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: "email, password y name son obligatorios" });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "Ese email ya existe" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, password: passwordHash, name },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });

    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.status(201).json({ user, token });
  } catch (e) {
    res.status(500).json({ error: "Error en register", detail: String(e?.message || e) });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email y password son obligatorios" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role, createdAt: user.createdAt },
      token,
    });
  } catch (e) {
    res.status(500).json({ error: "Error en login", detail: String(e?.message || e) });
  }
});

// Ruta protegida de prueba
app.get("/me", auth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: "Error en /me", detail: String(e?.message || e) });
  }
});

// ---------- TASKS (protegidas por usuario) ----------
app.get("/tasks", auth, async (req, res) => {
  try {
    const tasks = await prisma.task.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: "desc" },
    });
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ error: "Error listando tareas", detail: String(e?.message || e) });
  }
});

app.post("/tasks", auth, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: "title es obligatorio" });

  try {
    const task = await prisma.task.create({
      data: { title, userId: req.user.id },
    });
    res.status(201).json(task);
  } catch (e) {
    res.status(500).json({ error: "Error creando tarea", detail: String(e?.message || e) });
  }
});

app.patch("/tasks/:id", auth, async (req, res) => {
  const id = Number(req.params.id);
  const { title, completed } = req.body;

  if (Number.isNaN(id)) return res.status(400).json({ error: "id inválido" });

  try {
    const existing = await prisma.task.findFirst({
      where: { id, userId: req.user.id },
    });
    if (!existing) return res.status(404).json({ error: "Tarea no encontrada" });

    const updated = await prisma.task.update({
      where: { id },
      data: {
        ...(title !== undefined ? { title } : {}),
        ...(completed !== undefined ? { completed: Boolean(completed) } : {}),
      },
    });

    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: "Error actualizando tarea", detail: String(e?.message || e) });
  }
});

app.delete("/tasks/:id", auth, async (req, res) => {
  const id = Number(req.params.id);
  if (Number.isNaN(id)) return res.status(400).json({ error: "id inválido" });

  try {
    const existing = await prisma.task.findFirst({
      where: { id, userId: req.user.id },
    });
    if (!existing) return res.status(404).json({ error: "Tarea no encontrada" });

    await prisma.task.delete({ where: { id } });
    res.status(204).send();
  } catch (e) {
    res.status(500).json({ error: "Error borrando tarea", detail: String(e?.message || e) });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;

async function start() {
  try {
    if (!process.env.JWT_SECRET) {
      console.warn("⚠️ Falta JWT_SECRET en .env (Auth no funcionará bien)");
    }

    await prisma.$connect();
    console.log("✅ Prisma conectado a la DB");

    app.listen(PORT, () => {
      console.log(`✅ API corriendo en http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("❌ Error al iniciar:", err);
    process.exit(1);
  }
}

start();

// Cierre limpio
process.on("SIGINT", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
