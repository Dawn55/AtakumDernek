import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'
import  Button from '@/components/ui/Button'
import  Card from '@/components/ui/Card'
import  { CardBody} from '@/components/ui/Card'
import Link from 'next/link'
import { PrismaClient } from '@prisma/client'
import { formatDate } from '@/lib/utils'
import './globals.css'

const prisma = new PrismaClient()

export default async function HomePage() {
  // Server-side'da verileri çek
  let announcements = []
  let documents = []

  try {
    // Son 3 duyuruyu çek
    announcements = await prisma.announcement.findMany({
      where: { published: true },
      orderBy: { publishedAt: 'desc' },
      take: 3,
      select: {
        id: true,
        title: true,
        content: true,
        slug: true,
        publishedAt: true,
        createdAt: true,
        imageUrl: true
      }
    })

    // Son 3 belgeyi çek
    documents = await prisma.document.findMany({
      where: { published: true },
      orderBy: { createdAt: 'desc' },
      take: 3,
      select: {
        id: true,
        title: true,
        description: true,
        fileUrl: true,
        createdAt: true
      }
    })
  } catch (error) {
    console.error('Error fetching data:', error)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Header />
      
      {/* Enhanced Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background with parallax effect */}
        <div 
          className="absolute inset-0 bg-cover bg-center bg-fixed transform scale-105"
          style={{
            backgroundImage: 'url(https://i.imgur.com/F5njdFA.jpeg)', // 1920x800 boyutunda olmalı
            backgroundSize: 'cover',
            backgroundPosition: 'center'
          }}
        >
          {/* Enhanced overlay with gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-blue-900/80 via-purple-900/70 to-blue-800/80"></div>
          {/* Animated particles effect */}
          <div className="absolute inset-0 opacity-20">
            <div className="absolute top-20 left-20 w-2 h-2 bg-white rounded-full animate-pulse"></div>
            <div className="absolute top-40 right-32 w-1 h-1 bg-blue-200 rounded-full animate-ping"></div>
            <div className="absolute bottom-32 left-1/4 w-1.5 h-1.5 bg-white rounded-full animate-pulse animation-delay-1000"></div>
            <div className="absolute bottom-20 right-20 w-1 h-1 bg-blue-200 rounded-full animate-ping animation-delay-2000"></div>
          </div>
        </div>
        
        <div className="relative h-[700px] flex items-center justify-center">
          <div className="text-center max-w-5xl mx-auto px-4 z-10">
            {/* Animated title */}
            <div className="mb-8">
              <h1 className="text-5xl md:text-7xl font-bold mb-6 text-white leading-tight">
                <span className="inline-block animate-fade-in-up">Atakum</span>
                <span className="inline-block animate-fade-in-up animation-delay-200 bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent"> Bilişim</span>
                <span className="inline-block animate-fade-in-up animation-delay-400"> Derneği</span>
              </h1>
            </div>
            
            <p className="text-xl md:text-2xl mb-10 text-blue-100 animate-fade-in-up animation-delay-600 leading-relaxed max-w-3xl mx-auto">
              Bilişim teknolojilerinin geliştirilmesi ve yaygınlaştırılması için bir aradayız. 
              <span className="block mt-2 font-medium">Geleceği birlikte şekillendiriyoruz.</span>
            </p>
            
            <div className="space-x-4 animate-fade-in-up animation-delay-800">
              <Link href="/about">
                <Button 
                  size="lg" 
                  className="bg-white/95 backdrop-blur-sm text-blue-900 hover:bg-white hover:shadow-2xl hover:scale-105 transition-all duration-300 px-8 py-4 text-lg font-semibold rounded-full"
                >
                  Hakkımızda
                </Button>
              </Link>
              <Link href="/announcements">
                <Button 
                  size="lg" 
                  variant="outline" 
                  className="border-2 border-white/80 bg-white/10 backdrop-blur-sm text-white hover:bg-white hover:text-blue-800 transition-all duration-300 px-8 py-4 text-lg font-semibold rounded-full hover:scale-105"
                >
                  Duyurular
                </Button>
              </Link>
            </div>
          </div>
        </div>
        
        {/* Scroll indicator */}
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 text-white animate-bounce">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        </div>
      </section>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        {/* Latest Announcements */}
        <section className="mb-16">
          <div className="flex justify-between items-center mb-10">
            <div>
              <h2 className="text-4xl font-bold text-gray-900 mb-2">Son Duyurular</h2>
              <p className="text-gray-600 text-lg">En güncel haberler ve duyurularımız</p>
            </div>
            <Link href="/announcements">
              <Button variant="outline" className="hover:shadow-lg transition-all duration-300 hover:scale-105">
                Tümünü Gör
              </Button>
            </Link>
          </div>
          
          {announcements.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {announcements.map((announcement, index) => (
                <Card 
                  key={announcement.id} 
                  className="hover:shadow-2xl transition-all duration-300 hover:scale-105 border-0 bg-white/80 backdrop-blur-sm animate-fade-in-up overflow-hidden"
                  style={{ animationDelay: `${index * 200}ms` }}
                >
                  {/* Duyuru Resmi */}
                  {announcement.imageUrl ? (
                    <div className="relative h-48 overflow-hidden">
                      <img 
                        src={announcement.imageUrl} 
                        alt={announcement.title}
                        className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-110"
                      />
                      <div className="absolute top-4 left-4">
                        <span className="inline-block px-3 py-1 bg-blue-600/90 backdrop-blur-sm text-white text-xs font-semibold rounded-full">
                          DUYURU
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="h-48 bg-gradient-to-br from-blue-400/20 via-purple-400/20 to-pink-400/20 flex items-center justify-center">
                      <div className="text-center">
                        <div className="w-16 h-16 bg-blue-100/50 rounded-full flex items-center justify-center mx-auto mb-3">
                          <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                          </svg>
                        </div>
                        <span className="inline-block px-3 py-1 bg-blue-100/80 text-blue-800 text-xs font-semibold rounded-full">
                          DUYURU
                        </span>
                      </div>
                    </div>
                  )}

                  <CardBody className="p-6">
                    <h3 className="text-xl font-bold mb-3 text-gray-900">
                      <Link 
                        href={`/announcements/${announcement.slug}`}
                        className="hover:text-blue-600 transition-colors duration-300"
                      >
                        {announcement.title}
                      </Link>
                    </h3>
                    <p className="text-gray-500 text-sm mb-4 font-medium flex items-center">
                      <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
                      </svg>
                      {formatDate(announcement.publishedAt || announcement.createdAt)}
                    </p>
                    <p className="text-gray-700 line-clamp-3 leading-relaxed">
                      {announcement.content.substring(0, 120)}...
                    </p>
                    
                    {/* Devamını Oku Butonu */}
                    <div className="mt-4 pt-4 border-t border-gray-100">
                      <Link 
                        href={`/announcements/${announcement.slug}`}
                        className="inline-flex items-center text-blue-600 hover:text-blue-800 font-semibold transition-colors duration-300 group"
                      >
                        Devamını Oku
                        <svg className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </Link>
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <div className="max-w-md mx-auto bg-white/60 backdrop-blur-sm rounded-2xl p-8 border border-white/20 shadow-lg">
                <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-blue-400 to-purple-400 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">Henüz duyuru bulunmamaktadır</h3>
                <p className="text-gray-600">
                  Yakında yeni duyurular paylaşılacaktır.
                </p>
              </div>
            </div>
          )}
        </section>

        {/* Latest Documents */}
        <section className="mb-16">
          <div className="flex justify-between items-center mb-10">
            <div>
              <h2 className="text-4xl font-bold text-gray-900 mb-2">Son Belgeler</h2>
              <p className="text-gray-600 text-lg">İndirilebilir dokümanlar ve kaynaklar</p>
            </div>
            <Link href="/documents">
              <Button variant="outline" className="hover:shadow-lg transition-all duration-300 hover:scale-105">
                Tümünü Gör
              </Button>
            </Link>
          </div>
          
          {documents.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {documents.map((document, index) => (
                <Card 
                  key={document.id} 
                  className="hover:shadow-2xl transition-all duration-300 hover:scale-105 border-0 bg-white/80 backdrop-blur-sm animate-fade-in-up"
                  style={{ animationDelay: `${index * 200}ms` }}
                >
                  <CardBody className="p-6">
                    <div className="mb-4">
                      <span className="inline-block px-3 py-1 bg-green-100 text-green-800 text-xs font-semibold rounded-full">
                        BELGE
                      </span>
                    </div>
                    <h3 className="text-xl font-bold mb-3 text-gray-900">
                      {document.title}
                    </h3>
                    <p className="text-gray-500 text-sm mb-4 font-medium">
                      {formatDate(document.createdAt)}
                    </p>
                    <p className="text-gray-700 mb-6 leading-relaxed">
                      {document.description || 'Belge açıklaması bulunmamaktadır.'}
                    </p>
                    <a 
                      href={document.fileUrl}
                      download
                      className="inline-flex items-center text-blue-600 hover:text-blue-800 font-semibold transition-colors duration-300 group"
                    >
                      İndir 
                      <svg className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                      </svg>
                    </a>
                  </CardBody>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <div className="max-w-md mx-auto bg-white/60 backdrop-blur-sm rounded-2xl p-8 border border-white/20 shadow-lg">
                <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-r from-green-400 to-blue-400 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">Henüz belge bulunmamaktadır</h3>
                <p className="text-gray-600">
                  Yakında belgeler paylaşılacaktır.
                </p>
              </div>
            </div>
          )}
        </section>

        {/* Enhanced Features Section */}
        <section className="mb-16">
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Neler Yapıyoruz?
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Bilişim dünyasında fark yaratmak için çeşitli alanlarda aktif olarak çalışıyoruz
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
            <div className="text-center group hover:scale-105 transition-all duration-300">
              <div className="w-24 h-24 bg-gradient-to-br from-blue-100 to-purple-100 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:shadow-lg transition-all duration-300">
                <span className="text-4xl">🎓</span>
              </div>
              <h3 className="text-2xl font-bold mb-4 text-gray-900">Eğitim</h3>
              <p className="text-gray-600 leading-relaxed text-lg">
                Bilişim teknolojileri alanında kapsamlı eğitim programları ve interaktif seminerler düzenliyoruz.
              </p>
            </div>
            
            <div className="text-center group hover:scale-105 transition-all duration-300">
              <div className="w-24 h-24 bg-gradient-to-br from-green-100 to-blue-100 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:shadow-lg transition-all duration-300">
                <span className="text-4xl">🤝</span>
              </div>
              <h3 className="text-2xl font-bold mb-4 text-gray-900">Networking</h3>
              <p className="text-gray-600 leading-relaxed text-lg">
                Sektör profesyonellerini bir araya getiren değerli etkinlikler ve networking fırsatları sunuyoruz.
              </p>
            </div>
            
            <div className="text-center group hover:scale-105 transition-all duration-300">
              <div className="w-24 h-24 bg-gradient-to-br from-purple-100 to-pink-100 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:shadow-lg transition-all duration-300">
                <span className="text-4xl">💡</span>
              </div>
              <h3 className="text-2xl font-bold mb-4 text-gray-900">İnovasyon</h3>
              <p className="text-gray-600 leading-relaxed text-lg">
                Geleceğin teknolojilerini bugünden keşfediyoruz ve yenilikçi projeleri hayata geçiriyoruz.
              </p>
            </div>
          </div>
        </section>

        {/* Call to Action Section */}
        <section className="text-center py-16 px-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-3xl text-white mx-4">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            Bizimle Çalışmaya Başlayın
          </h2>
          <p className="text-xl mb-8 opacity-90 max-w-2xl mx-auto">
            Bilişim dünyasında birlikte büyüyelim ve teknolojinin gücüyle geleceği şekillendirelim
          </p>
          <div className="space-x-4">
            <Link href="/contact">
              <Button 
                size="lg"
                className="bg-white text-blue-600 hover:bg-gray-100 hover:scale-105 transition-all duration-300 px-8 py-4 text-lg font-semibold rounded-full"
              >
                İletişime Geçin
              </Button>
            </Link>
            <Link href="/membership">
              <Button 
                size="lg"
                variant="outline"
                className="border-2 border-white bg-transparent text-white hover:bg-white hover:text-blue-600 transition-all duration-300 px-8 py-4 text-lg font-semibold rounded-full hover:scale-105"
              >
                Üye Olun
              </Button>
            </Link>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  )
}