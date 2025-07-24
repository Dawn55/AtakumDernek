import { cn } from '@/lib/utils'

export default function Input({ 
  label, 
  error, 
  className, 
  ...props 
}) {
  return (
    <div className="mb-4">
      {label && (
        <label className="form-label">
          {label}
        </label>
      )}
      <input
        className={cn(
          'form-input',
          error && 'border-red-500',
          className
        )}
        {...props}
      />
      {error && (
        <p className="form-error">{error}</p>
      )}
    </div>
  )
}