import { PrismaClient } from "@prisma/client";
import Link from "next/link";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth"; // Auth konfigürasyonunuzun yolu
import Card from "../../../components/ui/Card";
import Button from "../../../components/ui/Button";

const prisma = new PrismaClient();

export default async function AdminUsersPage() {
  // Giriş yapmış kullanıcının session bilgisini al
  const session = await getServerSession(authOptions);
  const currentUserEmail = session?.user?.email;

  // Giriş yapmış kullanıcı hariç diğer kullanıcıları getir
  const users = await prisma.user.findMany({
    where: {
      email: {
        not: currentUserEmail
      }
    },
    orderBy: { createdAt: "desc" }
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900">Kullanıcı Yönetimi</h1>
        <div className="text-sm text-gray-500">
          Toplam: {users.length} kullanıcı
        </div>
      </div>

      <div className="grid gap-6">
        {users.map((user) => (
          <Card key={user.id} className="p-6 hover:shadow-lg transition-shadow">
            <div className="flex justify-between items-start">
              <div className="flex items-center space-x-4">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-semibold shadow-md">
                  {user.name?.charAt(0).toUpperCase() || user.email.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-gray-900">
                    {user.name || "İsimsiz Kullanıcı"}
                  </h3>
                  <p className="text-gray-600">{user.email}</p>
                  <div className="flex items-center space-x-4 text-sm text-gray-500 mt-2">
                    <span className="flex items-center">
                      📅 {new Date(user.createdAt).toLocaleDateString("tr-TR")}
                    </span>
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                      user.role === 1 
                        ? "bg-red-100 text-red-800 border border-red-200" 
                        : "bg-green-100 text-green-800 border border-green-200"
                    }`}>
                      {user.role === 1 ? "👑 Admin" : "👤 Kullanıcı"}
                    </span>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2 ml-4">
                <Link href={`/admin/users/${user.id}/edit`}>
                  <Button variant="outline" size="sm" className="hover:bg-blue-50">
                    ✏️ Düzenle
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {users.length === 0 && (
        <div className="text-center py-12">
          <div className="text-6xl mb-4">👥</div>
          <p className="text-gray-500 text-lg mb-2">Henüz başka kullanıcı bulunmamaktadır.</p>
          <p className="text-gray-400 text-sm">Yeni kullanıcılar kayıt olduğunda burada görünecektir.</p>
        </div>
      )}
    </div>
  );
}