"use client";

import Link from 'next/link'
import { useSession, signOut } from 'next-auth/react'
import Button from '@/components/ui/Button'
import { isAdmin } from '@/lib/utils'

export function Header() {
  const { data: session } = useSession()
  
  return (
    <header className="bg-white shadow-lg border-b-2 border-gray-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-20">
          <Link href="/" className="flex items-center group">
            <img 
              src="https://i.imgur.com/bNSIi2C.jpeg" 
              alt="Atakum Bilişim Derneği" 
              className="h-12 w-auto group-hover:scale-105 transition-transform duration-200"
            />
          </Link>
          
          <nav className="hidden md:flex space-x-10">
            <Link 
              href="/" 
              className="text-lg font-medium text-gray-700 hover:text-blue-600 hover:scale-105 transition-all duration-200 relative group"
            >
              Ana Sayfa
              <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-blue-600 group-hover:w-full transition-all duration-300"></span>
            </Link>
            <Link 
              href="/announcements" 
              className="text-lg font-medium text-gray-700 hover:text-blue-600 hover:scale-105 transition-all duration-200 relative group"
            >
              Duyurular
              <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-blue-600 group-hover:w-full transition-all duration-300"></span>
            </Link>
            <Link 
              href="/documents" 
              className="text-lg font-medium text-gray-700 hover:text-blue-600 hover:scale-105 transition-all duration-200 relative group"
            >
              Belgeler
              <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-blue-600 group-hover:w-full transition-all duration-300"></span>
            </Link>
            <Link 
              href="/about" 
              className="text-lg font-medium text-gray-700 hover:text-blue-600 hover:scale-105 transition-all duration-200 relative group"
            >
              Hakkımızda
              <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-blue-600 group-hover:w-full transition-all duration-300"></span>
            </Link>
          </nav>
          
          <div className="flex items-center space-x-5">
            {session ? (
              <>
                {isAdmin(session.user) && (
                  <Link href="/admin/announcements">
                    <Button 
                      variant="outline" 
                      size="lg"
                      className="text-base font-medium border-2 hover:bg-gray-50 hover:scale-105 transition-all duration-200"
                    >
                      Admin Panel
                    </Button>
                  </Link>
                )}
                <div className="flex items-center space-x-4 bg-gray-50 px-4 py-2 rounded-lg">
                  <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                    <span className="text-white font-semibold text-sm">
                      {session.user.name?.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <span className="text-base font-medium text-gray-700">
                    {session.user.name}
                  </span>
                  <Button 
                    variant="ghost" 
                    size="lg"
                    className="text-base font-medium text-red-600 hover:text-red-700 hover:bg-red-50 hover:scale-105 transition-all duration-200"
                    onClick={() => signOut()}
                  >
                    Çıkış
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex items-center space-x-3">
                <Link href="/auth/signin">
                  <Button 
                    variant="ghost"
                    size="lg"
                    className="text-base font-medium text-gray-700 hover:text-blue-600 hover:bg-blue-50 hover:scale-105 transition-all duration-200"
                  >
                    Giriş Yap
                  </Button>
                </Link>
                <Link href="/auth/register">
                  <Button 
                    size="lg"
                    className="text-base font-semibold bg-blue-600 hover:bg-blue-700 hover:scale-105 transition-all duration-200 shadow-md"
                  >
                    Kayıt Ol
                  </Button>
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}