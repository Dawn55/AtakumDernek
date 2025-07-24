import { PrismaClient } from "@prisma/client";
import { notFound } from "next/navigation";
import UserForm from "../../../../../components/forms/UserForm";
import Card from "../../../../../components/ui/Card";

const prisma = new PrismaClient();

export default async function EditUserPage({ params }) {
  const user = await prisma.user.findUnique({
    where: { id: params.id }
  });

  if (!user) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Kullanıcı Düzenle</h1>
        <p className="text-gray-600 mt-2">
          "{user.name || user.email}" kullanıcısını düzenleyin.
        </p>
      </div>

      <Card className="p-6">
        <UserForm user={user} />
      </Card>
    </div>
  );
}