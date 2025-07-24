import { PrismaClient } from "@prisma/client";
import Link from "next/link";
import Card from "../../../components/ui/Card";
import Button from "../../../components/ui/Button";

const prisma = new PrismaClient();

export default async function AdminAnnouncementsPage() {
  const announcements = await prisma.announcement.findMany({
    orderBy: { createdAt: "desc" }
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900">Duyuru Yönetimi</h1>
        <Link href="/admin/announcements/create">
          <Button>Yeni Duyuru Ekle</Button>
        </Link>
      </div>

      <div className="grid gap-6">
        {announcements.map((announcement) => (
          <Card key={announcement.id} className="p-6">
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  {announcement.title}
                </h3>
                <p className="text-gray-600 mb-4 line-clamp-2">
                  {announcement.content}
                </p>
                <div className="flex items-center space-x-4 text-sm text-gray-500">
                  <span>
                    {new Date(announcement.createdAt).toLocaleDateString("tr-TR")}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs ${
                    announcement.published 
                      ? "bg-green-100 text-green-800" 
                      : "bg-yellow-100 text-yellow-800"
                  }`}>
                    {announcement.published ? "Yayında" : "Taslak"}
                  </span>
                </div>
              </div>
              <div className="flex space-x-2 ml-4">
                <Link href={`/admin/announcements/${announcement.id}/edit`}>
                  <Button variant="outline" size="sm">Düzenle</Button>
                </Link>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {announcements.length === 0 && (
        <div className="text-center py-12">
          <p className="text-gray-500 text-lg">Henüz duyuru bulunmamaktadır.</p>
          <Link href="/admin/announcements/create" className="mt-4 inline-block">
            <Button>İlk Duyurunuzu Ekleyin</Button>
          </Link>
        </div>
      )}
    </div>
  );
}