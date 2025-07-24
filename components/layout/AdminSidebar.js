'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { useSession } from 'next-auth/react'

export default function AdminSidebar() {
  const pathname = usePathname()
  const { data: session } = useSession()

  const menuItems = [
    { href: '/admin/announcements', label: 'Duyurular', icon: '📢', description: 'Sistem duyurularını yönet' },
    { href: '/admin/documents', label: 'Belgeler', icon: '📄', description: 'Belge arşivini düzenle' },
    { href: '/admin/users', label: 'Kullanıcılar', icon: '👥', description: 'Kullanıcı hesaplarını kontrol et' },
  ]

  return (
    <div className="w-80 bg-gradient-to-b from-slate-900 via-slate-800 to-slate-900 text-white min-h-screen flex flex-col shadow-2xl border-r border-slate-700">
      {/* Header */}
      <div className="p-8 border-b border-slate-700/50 bg-gradient-to-r from-blue-900/20 to-purple-900/20">
        <div className="flex items-center space-x-3 mb-2">
          <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
            <span className="text-xl">⚡</span>
          </div>
          <div>
            <h2 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              Admin Panel
            </h2>
            <p className="text-slate-400 text-sm">Yönetim Merkezi</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-6 py-8 space-y-3">
        <div className="mb-6">
          <h3 className="text-xs uppercase tracking-wider text-slate-400 font-semibold px-3 mb-4">
            Menü
          </h3>
        </div>
        
        {menuItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              'group flex items-start px-4 py-4 rounded-xl transition-all duration-300 ease-in-out transform hover:scale-[1.02] hover:shadow-lg',
              pathname === item.href
                ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg shadow-blue-500/25'
                : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
            )}
          >
            <div className="flex items-center space-x-4 flex-1">
              <div className={cn(
                'w-12 h-12 rounded-lg flex items-center justify-center transition-all duration-300',
                pathname === item.href
                  ? 'bg-white/20 shadow-inner'
                  : 'bg-slate-700/50 group-hover:bg-slate-600/50'
              )}>
                <span className="text-xl">{item.icon}</span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-base truncate">{item.label}</span>
                  {pathname === item.href && (
                    <div className="w-2 h-2 bg-white rounded-full animate-pulse"></div>
                  )}
                </div>
                <p className="text-xs text-slate-400 group-hover:text-slate-300 mt-1 truncate">
                  {item.description}
                </p>
              </div>
            </div>
          </Link>
        ))}
      </nav>

      {/* User Info Section */}
      <div className="px-6 py-4 border-t border-slate-700/50">
        <div className="flex items-center space-x-3 p-3 rounded-lg bg-slate-800/40">
          <div className="w-8 h-8 bg-gradient-to-r from-green-400 to-blue-500 rounded-full flex items-center justify-center">
            <span className="text-sm font-bold text-white">{session?.user?.name?.charAt(0).toUpperCase()}</span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-white truncate">{session?.user?.name}</p>
            <p className="text-xs text-slate-400">Yönetici</p>
          </div>
        </div>
      </div>

      {/* Back to Site Button */}
      <div className="p-6 border-t border-slate-700/50 bg-slate-800/20">
        <Link
          href="/"
          className="group flex items-center justify-center w-full px-4 py-3 rounded-xl bg-slate-800/60 hover:bg-slate-700 text-slate-300 hover:text-white transition-all duration-300 ease-in-out transform hover:scale-[1.02] hover:shadow-md"
        >
          <span className="text-lg mr-3 group-hover:animate-bounce">🔙</span>
          <span className="font-medium">Siteye Geri Dön</span>
        </Link>
      </div>
    </div>
  )
}