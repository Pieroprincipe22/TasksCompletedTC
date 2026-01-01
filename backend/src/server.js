require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const prisma = new PrismaClient();

/** ---------- Config ---------- */
const PORT = Number(process.env.PORT) || 4000;
const NODE_ENV = process.env.NODE_ENV || "development";
const JWT_SECRET = process.env.JWT_SECRET || "";

// Permite varios orígenes separados por coma: "http://localhost:3000,http://localhost:5173"
const DEFAULT_ORIGINS = ["http://localhost:3000", "http://localhost:5173"];
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const originAllowlist = new Set(ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : DEFAULT_ORIGINS);

app.use(
  cors({
    origin: (origin, cb) => {
      // Permitir herramientas tipo curl/postman (sin origin)
      if (!origin) return cb(null, true);
      return originAllowlist.has(origin)
        ? cb(null, true)
        : cb(new Error(`CORS bloqueado para origin: ${origin}`));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "1mb" }));

/** ---------- Helpers ---------- */
function isPrismaUniqueError(e) {
  return Boolean(e && typeof e === "object" && e.code === "P2002");
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Token requerido (Bearer)" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

/** ---------- Router (se monta en / y en /api) ---------- */
const router = express.Router();

// Raíz
router.get("/", (req, res) => {
  res.send("API corriendo ✅");
});

// Health
router.get("/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, db: true });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: String(e?.message || e) });
  }
});

// USERS (básico)
router.get("/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: "Error listando usuarios", detail: String(e?.message || e) });
  }
});

// Este endpoint queda SOLO para desarrollo y además HASHEA password
router.post("/users", async (req, res) => {
  if (NODE_ENV !== "development") {
    return res.status(404).json({ error: "Not found" });
  }

  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: "email, password y name son obligatorios" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: passwordHash, name },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });

    res.status(201).json(user);
  } catch (e) {
    if (isPrismaUniqueError(e) || String(e).includes("Unique constraint")) {
      return res.status(409).json({ error: "Ese email ya existe" });
    }
    res.status(500).json({ error: "Error creando usuario", detail: String(e?.message || e) });
  }
});

// AUTH
router.post("/auth/register", async (req, res) => {
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
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.status(201).json({ user, token });
  } catch (e) {
    res.status(500).json({ error: "Error en register", detail: String(e?.message || e) });
  }
});

router.post("/auth/login", async (req, res) => {
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
      JWT_SECRET,
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
router.get("/me", auth, async (req, res) => {
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

// TASKS (protegidas por usuario)
router.get("/tasks", auth, async (req, res) => {
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

router.post("/tasks", auth, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: "title es obligatorio" });

  try {
    const task = await prisma.task.create({
      data: { title: String(title).trim(), userId: req.user.id },
    });
    res.status(201).json(task);
  } catch (e) {
    res.status(500).json({ error: "Error creando tarea", detail: String(e?.message || e) });
  }
});

router.patch("/tasks/:id", auth, async (req, res) => {
  const id = Number(req.params.id);
  const { title, completed } = req.body;

  if (Number.isNaN(id)) return res.status(400).json({ error: "id inválido" });

  const data = {
    ...(title !== undefined ? { title: String(title).trim() } : {}),
    ...(completed !== undefined ? { completed: Boolean(completed) } : {}),
  };

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: "Nada que actualizar" });
  }

  try {
    const existing = await prisma.task.findFirst({
      where: { id, userId: req.user.id },
    });
    if (!existing) return res.status(404).json({ error: "Tarea no encontrada" });

    const updated = await prisma.task.update({
      where: { id },
      data,
    });

    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: "Error actualizando tarea", detail: String(e?.message || e) });
  }
});

router.delete("/tasks/:id", auth, async (req, res) => {
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

// Montamos en / y en /api para compatibilidad
app.use(router);
app.use("/api", router);

/** ---------- Start + shutdown ---------- */
async function start() {
  if (!JWT_SECRET) {
    throw new Error("Falta JWT_SECRET en el .env");
  }

  await prisma.$connect();
  console.log("✅ Prisma conectado a la DB");

  const server = app.listen(PORT, () => {
    console.log(`✅ API corriendo en http://localhost:${PORT}`);
  });

  const shutdown = async (signal) => {
    try {
      console.log(`\n🛑 ${signal} recibido. Cerrando...`);
      server.close(async () => {
        await prisma.$disconnect();
        process.exit(0);
      });
    } catch {
      process.exit(1);
    }
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

start().catch((err) => {
  console.error("❌ Error al iniciar:", err);
  process.exit(1);
});
