'use client';

import { useSearchParams } from 'next/navigation';
import Card from '../../../components/ui/Card';
import Button from '../../../components/ui/Button';

export default function AuthError() {
  const searchParams = useSearchParams();
  const error = searchParams.get('error');

  const getErrorMessage = (error) => {
    switch (error) {
      case 'OAuthCallback':
        return 'Google giriş işlemi sırasında bir hata oluştu. Lütfen tekrar deneyin.';
      case 'OAuthSignin':
        return 'OAuth servis sağlayıcısıyla bağlantı kurulamadı.';
      case 'OAuthCreateAccount':
        return 'Hesap oluşturulurken bir hata oluştu.';
      case 'EmailCreateAccount':
        return 'E-posta ile hesap oluşturulurken bir hata oluştu.';
      case 'Callback':
        return 'Giriş callback işlemi başarısız oldu.';
      case 'OAuthAccountNotLinked':
        return 'Bu e-posta adresi başka bir giriş yöntemiyle zaten kullanılıyor.';
      case 'EmailSignin':
        return 'E-posta gönderilirken bir hata oluştu.';
      case 'CredentialsSignin':
        return 'E-posta veya şifre hatalı.';
      case 'SessionRequired':
        return 'Bu sayfaya erişmek için giriş yapmanız gerekiyor.';
      default:
        return 'Bilinmeyen bir hata oluştu.';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="w-16 h-16 bg-gradient-to-br from-red-600 to-pink-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-xl">!</span>
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-bold text-gray-900">
          Giriş Hatası
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          {getErrorMessage(error)}
        </p>
        {error && (
          <p className="mt-1 text-center text-xs text-gray-500">
            Hata kodu: {error}
          </p>
        )}
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <Card className="p-8">
          <div className="space-y-4">
            <Button
              onClick={() => window.location.href = '/auth/signin'}
              className="w-full"
            >
              Giriş Sayfasına Dön
            </Button>
            
            <Button
              onClick={() => window.location.href = '/'}
              variant="outline"
              className="w-full"
            >
              Ana Sayfaya Git
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}