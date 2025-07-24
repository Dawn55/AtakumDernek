import { PrismaClient } from "@prisma/client";
import Link from "next/link";
import Card, { CardImage, CardBody, CardFooter } from "../../components/ui/Card";
import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'

const prisma = new PrismaClient();

export default async function AnnouncementsPage() {
  const announcements = await prisma.announcement.findMany({
    where: { published: true },
    orderBy: { publishedAt: "desc" }
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-purple-50/30">
      <Header />
      <div className="relative bg-gradient-to-r from-blue-600 to-purple-600 py-16">
        <div className="absolute inset-0 bg-black/10"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl font-bold text-white mb-4 drop-shadow-lg">
              Duyurular
            </h1>
            <p className="text-xl text-blue-100 max-w-2xl mx-auto drop-shadow-md">
              Atakum Bileşim Derneği'nin güncel duyurularını burada bulabilirsiniz.
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          {announcements.map((announcement) => (
            <Card key={announcement.id} className="group hover:scale-[1.02] transition-all duration-300">
              {/* Resim varsa göster, yoksa varsayılan gradient */}
              {announcement.imageUrl ? (
                <CardImage 
                  src={announcement.imageUrl} 
                  alt={announcement.title}
                />
              ) : (
                <div className="h-48 bg-gradient-to-br from-blue-400/20 via-purple-400/20 to-pink-400/20 rounded-t-xl flex items-center justify-center">
                  <div className="text-center p-6">
                    <svg className="w-12 h-12 mx-auto text-blue-400/60 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                    </svg>
                    <p className="text-sm text-gray-500 font-medium">Duyuru</p>
                  </div>
                </div>
              )}
              
              <CardBody>
                <div className="flex items-center justify-between mb-3">
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100/80 text-blue-800 backdrop-blur-sm">
                    <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
                    </svg>
                    {new Date(announcement.publishedAt || announcement.createdAt).toLocaleDateString("tr-TR")}
                  </span>
                </div>
                
                <h3 className="text-xl font-bold text-gray-900 mb-3 line-clamp-2 group-hover:text-blue-600 transition-colors duration-200">
                  {announcement.title}
                </h3>
                
                <p className="text-gray-600 mb-4 line-clamp-3 leading-relaxed">
                  {announcement.content}
                </p>
              </CardBody>

              <CardFooter>
                <Link 
                  href={`/announcements/${announcement.slug}`}
                  className="inline-flex items-center justify-center w-full px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-500 text-white font-medium rounded-lg hover:from-blue-600 hover:to-purple-600 transform hover:scale-105 transition-all duration-200 shadow-md hover:shadow-lg"
                >
                  Devamını Oku
                  <svg className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              </CardFooter>
            </Card>
          ))}
        </div>

        {announcements.length === 0 && (
          <div className="text-center py-16">
            <div className="max-w-md mx-auto bg-white/60 backdrop-blur-sm rounded-2xl p-8 border border-white/20 shadow-lg">
              <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full flex items-center justify-center">
                <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-gray-900 mb-2">Henüz duyuru bulunmamaktadır</h3>
              <p className="text-gray-600">
                Yakında yeni duyurular paylaşılacaktır.
              </p>
            </div>
          </div>
        )}
      </div>
      <Footer />
    </div>
  );
}