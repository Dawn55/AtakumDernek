import { cn } from '@/lib/utils'

// Main Card component (default export)
export default function Card({ children, className, ...props }) {
  return (
    <div className={cn('bg-white/80 backdrop-blur-sm border border-white/20 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 hover:bg-white/90', className)} {...props}>
      {children}
    </div>
  )
}

// Named exports for sub-components
export function CardHeader({ children, className, ...props }) {
  return (
    <div className={cn('px-6 pt-6', className)} {...props}>
      {children}
    </div>
  )
}

export function CardBody({ children, className, ...props }) {
  return (
    <div className={cn('px-6 py-4', className)} {...props}>
      {children}
    </div>
  )
}

export function CardFooter({ children, className, ...props }) {
  return (
    <div className={cn('px-6 pb-6', className)} {...props}>
      {children}
    </div>
  )
}

// Yeni resim komponenti
export function CardImage({ src, alt, className, ...props }) {
  return (
    <div className={cn('relative overflow-hidden rounded-t-xl', className)} {...props}>
      <img 
        src={src} 
        alt={alt}
        className="w-full h-48 object-cover transition-transform duration-300 hover:scale-105"
      />
      <div className="absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0 hover:opacity-100 transition-opacity duration-300" />
    </div>
  )
}