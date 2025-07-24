import { cn } from '@/lib/utils'

export function Textarea({ 
  label, 
  error, 
  className, 
  rows = 4,
  ...props 
}) {
  return (
    <div className="mb-4">
      {label && (
        <label className="form-label">
          {label}
        </label>
      )}
      <textarea
        rows={rows}
        className={cn(
          'form-textarea',
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
