const prisma = require("../prisma");

async function main() {
  const company = await prisma.company.create({
    data: {
      name: "TasksCompleted",
    },
  });

  await prisma.user.create({
    data: {
      email: "admin@taskscompleted.com",
      name: "Admin",
      password: "admin123", // luego la ciframos
      role: "ADMIN",
      companyId: company.id,
    },
  });

  console.log("✅ Admin creado");
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
