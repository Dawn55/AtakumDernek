'use client'

import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'
import  Card from '@/components/ui/Card'
import  { CardBody} from '@/components/ui/Card'

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        <section className="text-center mb-12">
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 mb-6">
            Hakkımızda
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Atakum Bilişim Derneği, bilişim teknolojilerinin geliştirilmesi ve yaygınlaştırılması 
            amacıyla kurulan bir sivil toplum kuruluşudur.
          </p>
        </section>

        {/* Mission & Vision */}
        <section className="mb-12">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <Card>
              <CardBody>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Misyonumuz</h2>
                <p className="text-gray-700 leading-relaxed">
                  Bilişim teknolojileri alanında eğitim, araştırma ve geliştirme faaliyetleri 
                  yürüterek toplumun dijital dönüşümüne katkı sağlamak. Sektör profesyonellerini 
                  bir araya getirerek bilgi paylaşımı ve işbirliği ortamı oluşturmak.
                </p>
              </CardBody>
            </Card>
            
            <Card>
              <CardBody>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Vizyonumuz</h2>
                <p className="text-gray-700 leading-relaxed">
                  Bilişim teknolojileri alanında öncü bir dernek olarak, yenilikçi projeler 
                  geliştiren, eğitim kalitesini yükselten ve sektörün gelişimine katkı sağlayan 
                  bir kuruluş olmak.
                </p>
              </CardBody>
            </Card>
          </div>
        </section>

        {/* About Content */}
        <section className="mb-12">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                Kimiz?
              </h2>
              <div className="prose prose-lg">
                <p className="text-gray-700 leading-relaxed mb-4">
                  Atakum Bilişim Derneği, 2024 yılında Samsun'un Atakum ilçesinde kurulan 
                  genç ve dinamik bir sivil toplum kuruluşudur. Derneğimiz, bilişim sektöründe 
                  faaliyet gösteren profesyoneller, akademisyenler ve öğrenciler tarafından 
                  oluşturulmuştur.
                </p>
                
                <p className="text-gray-700 leading-relaxed mb-4">
                  Temel amacımız, bilişim teknolojilerinin geliştirilmesi ve yaygınlaştırılması 
                  yoluyla toplumsal fayda sağlamaktır. Bu doğrultuda eğitim programları, 
                  seminerler, konferanslar ve workshop'lar düzenlemekteyiz.
                </p>
                
                <p className="text-gray-700 leading-relaxed">
                  Sektörel işbirliği ve bilgi paylaşımına önem veren derneğimiz, üyelerimiz 
                  ve geniş katılımcı kitlemiz ile birlikte bilişim ekosisteminin gelişmesine 
                  katkı sağlamaya devam etmektedir.
                </p>
              </div>
            </div>
            
            <div>
              <img 
                src="/images/about-image.jpg" 
                alt="Atakum Bilişim Derneği Hakkında"
                className="rounded-lg shadow-lg w-full h-auto"
                style={{ aspectRatio: '4/3' }}
              />
            </div>
          </div>
        </section>

        {/* Values */}
        <section className="mb-12">
          <h2 className="text-3xl font-bold text-gray-900 text-center mb-12">
            Değerlerimiz
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🎯</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Kalite</h3>
              <p className="text-gray-600">
                Yaptığımız her işte en yüksek kalite standartlarını hedefliyoruz.
              </p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🤝</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">İşbirliği</h3>
              <p className="text-gray-600">
                Birlikte çalışmanın gücüne inanıyor ve işbirliğini destekliyoruz.
              </p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">💡</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Yenilikçilik</h3>
              <p className="text-gray-600">
                Sürekli öğrenme ve yenilikçi çözümler geliştirme odaklıyız.
              </p>
            </div>
            
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🌟</span>
              </div>
              <h3 className="text-xl font-semibold mb-2">Şeffaflık</h3>
              <p className="text-gray-600">
                Tüm faaliyetlerimizde açık ve şeffaf olmaya özen gösteriyoruz.
              </p>
            </div>
          </div>
        </section>

        {/* Contact Info */}
        <section>
          <Card>
            <CardBody>
              <h2 className="text-2xl font-bold text-gray-900 mb-6 text-center">
                İletişim Bilgileri
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
                <div>
                  <h3 className="text-lg font-semibold mb-2">Adres</h3>
                  <p className="text-gray-600">
                    Atakum/Samsun<br />
                    Türkiye
                  </p>
                </div>
                <div>
                  <h3 className="text-lg font-semibold mb-2">Telefon</h3>
                  <p className="text-gray-600">
                    +90 362 XXX XX XX
                  </p>
                </div>
                <div>
                  <h3 className="text-lg font-semibold mb-2">E-posta</h3>
                  <p className="text-gray-600">
                    info@atakumbilesim.org
                  </p>
                </div>
              </div>
            </CardBody>
          </Card>
        </section>
      </main>
      <Footer />
    </div>
  )
}