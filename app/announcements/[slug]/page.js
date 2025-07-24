import { PrismaClient } from "@prisma/client";
import { notFound } from "next/navigation";
import Link from "next/link";
import Card from "../../../components/ui/Card";
import { Header } from '@/components/layout/Header';
import { Footer } from '@/components/layout/Footer';

const prisma = new PrismaClient();

export default async function AnnouncementDetailPage({ params }) {
  const announcement = await prisma.announcement.findUnique({
    where: { 
      slug: params.slug,
      published: true 
    }
  });

  if (!announcement) {
    notFound();
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-purple-50/30">
      <Header />
      
      {/* Enhanced Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background with image or gradient */}
        <div 
          className="absolute inset-0 bg-cover bg-center bg-fixed transform scale-105"
          style={{
            backgroundImage: announcement.imageUrl ? `url(${announcement.imageUrl})` : 'url(https://i.imgur.com/F5njdFA.jpeg)', // 1920x800 boyutunda olmalı
            backgroundSize: 'cover',
            backgroundPosition: 'center'
          }}
        >
          {/* Enhanced overlay with matching gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-blue-600/85 to-purple-600/85"></div>
          {/* Animated particles effect */}
          <div className="absolute inset-0 opacity-20">
            <div className="absolute top-20 left-20 w-2 h-2 bg-white rounded-full animate-pulse"></div>
            <div className="absolute top-40 right-32 w-1 h-1 bg-blue-200 rounded-full animate-ping"></div>
            <div className="absolute bottom-32 left-1/4 w-1.5 h-1.5 bg-white rounded-full animate-pulse animation-delay-1000"></div>
            <div className="absolute bottom-20 right-20 w-1 h-1 bg-blue-200 rounded-full animate-ping animation-delay-2000"></div>
          </div>
        </div>
        
        <div className="relative h-[400px] flex items-center justify-center">
          <div className="text-center max-w-5xl mx-auto px-4 z-10">
            {/* Back button */}
            <div className="mb-6">
              <Link 
                href="/announcements"
                className="inline-flex items-center text-blue-100 hover:text-white mb-4 transition-colors duration-200 bg-black/20 backdrop-blur-sm px-4 py-2 rounded-full"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Duyurulara Geri Dön
              </Link>
            </div>
            
            {/* Badge */}
            <div className="mb-4">
              <span className="inline-block px-4 py-2 bg-blue-600/90 backdrop-blur-sm text-white text-sm font-semibold rounded-full">
                DUYURU
              </span>
            </div>
            
            {/* Title */}
            <h1 className="text-3xl md:text-4xl font-bold mb-4 text-white leading-tight drop-shadow-lg">
              {announcement.title}
            </h1>
            
            {/* Date */}
            <div className="flex items-center justify-center text-blue-100 mb-6">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
              </svg>
              <span className="text-lg font-medium">
                {new Date(announcement.publishedAt || announcement.createdAt).toLocaleDateString("tr-TR", {
                  year: "numeric",
                  month: "long",
                  day: "numeric"
                })}
              </span>
            </div>
          </div>
        </div>
        
      </section>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-xl hover:shadow-2xl transition-shadow duration-300">
          {/* İçerik */}
          <div className="p-8">
            {/* Tarih Bilgisi */}
            <div className="flex items-center mb-6 text-gray-500">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
              </svg>
              <span className="text-sm font-medium">
                Yayınlanma: {new Date(announcement.publishedAt || announcement.createdAt).toLocaleDateString("tr-TR", {
                  year: "numeric",
                  month: "long",
                  day: "numeric",
                  weekday: "long"
                })}
              </span>
            </div>

            {/* Ana İçerik */}
            <div className="prose prose-lg max-w-none">
              <div className="text-gray-800 leading-relaxed text-lg whitespace-pre-wrap font-['Inter',system-ui,sans-serif]">
                {announcement.content}
              </div>
            </div>
          </div>
        </Card>

        {/* Navigation Buttons */}
        <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
          <Link 
            href="/announcements"
            className="inline-flex items-center justify-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-500 text-white font-medium rounded-lg hover:from-blue-600 hover:to-purple-600 transform hover:scale-105 transition-all duration-200 shadow-md hover:shadow-lg"
          >
            Tüm Duyurular
          </Link>
          
          <Link 
            href="/"
            className="inline-flex items-center justify-center px-6 py-3 border border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition-colors duration-200"
          >
            Ana Sayfa
          </Link>
        </div>
      </div>
      
      <Footer />
    </div>
  );
}