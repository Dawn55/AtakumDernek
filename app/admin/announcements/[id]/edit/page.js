import { PrismaClient } from "@prisma/client";
import { notFound } from "next/navigation";
import AnnouncementForm from "../../../../../components/forms/AnnouncementForm.js";
import Card from "../../../../../components/ui/Card";

const prisma = new PrismaClient();

export default async function EditAnnouncementPage({ params }) {
  const announcement = await prisma.announcement.findUnique({
    where: { id: params.id }
  });

  if (!announcement) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Duyuru Düzenle</h1>
        <p className="text-gray-600 mt-2">
          "{announcement.title}" duyurusunu düzenleyin.
        </p>
      </div>

      <Card className="p-6">
        <AnnouncementForm announcement={announcement} />
      </Card>
    </div>
  );
}