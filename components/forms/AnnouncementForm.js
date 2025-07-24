"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createAnnouncement, updateAnnouncement } from "@/lib/actions/announcements";
import Button from "../ui/Button";
import Input from "../ui/Input";

export default function AnnouncementForm({ announcement = null }) {
  const router = useRouter();
  const [formData, setFormData] = useState({
    title: announcement?.title || "",
    content: announcement?.content || "",
    slug: announcement?.slug || "",
    imageUrl: announcement?.imageUrl || "",
    published: announcement?.published || false,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState("");
  const [imageInputType, setImageInputType] = useState("url"); // "url" veya "file"
  const [previewImage, setPreviewImage] = useState(announcement?.imageUrl || "");

  const generateSlug = (title) => {
    return title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/[\s_-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .replace(/ç/g, 'c')
      .replace(/ğ/g, 'g')
      .replace(/ı/g, 'i')
      .replace(/ö/g, 'o')
      .replace(/ş/g, 's')
      .replace(/ü/g, 'u');
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value
    }));

    // URL değiştiğinde preview güncelle
    if (name === "imageUrl") {
      setPreviewImage(value);
    }

    // Yeni duyuru oluşturuluyorsa title'dan otomatik slug oluştur
    if (name === "title" && !announcement) {
      setFormData(prev => ({
        ...prev,
        slug: generateSlug(value)
      }));
    }

    // Clear error when user starts typing
    if (error) setError("");
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Dosya boyutu kontrolü (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      setError("Dosya boyutu 5MB'dan küçük olmalıdır.");
      return;
    }

    // Dosya tipi kontrolü
    if (!file.type.startsWith('image/')) {
      setError("Lütfen sadece resim dosyası seçin.");
      return;
    }

    setIsUploading(true);
    setError("");

    try {
      // FormData oluştur
      const formData = new FormData();
      formData.append('file', file);

      // Dosyayı yükle
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        setFormData(prev => ({
          ...prev,
          imageUrl: data.url
        }));
        setPreviewImage(data.url);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Yükleme başarısız');
      }
    } catch (error) {
      console.error('Upload error:', error);
      setError(`Resim yükleme hatası: ${error.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const removeImage = () => {
    setFormData(prev => ({
      ...prev,
      imageUrl: ""
    }));
    setPreviewImage("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError("");

    try {
      let result;
      
      if (announcement) {
        // Güncelleme
        result = await updateAnnouncement(announcement.id, formData);
      } else {
        // Yeni oluşturma
        result = await createAnnouncement(formData);
      }

      if (result.success) {
        router.push("/admin/announcements");
        router.refresh();
      } else {
        setError(result.error || "İşlem başarısız");
      }
    } catch (error) {
      console.error("Form gönderim hatası:", error);
      setError("Bir hata oluştu. Lütfen tekrar deneyin.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white shadow-lg rounded-lg p-8">
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            {announcement ? "Duyuru Düzenle" : "Yeni Duyuru Oluştur"}
          </h2>
          <p className="text-gray-600">
            {announcement ? "Mevcut duyuru bilgilerini güncelleyin" : "Yeni bir sistem duyurusu oluşturun"}
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
            <div className="flex">
              <div className="text-red-400">⚠️</div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">Hata</h3>
                <div className="mt-2 text-sm text-red-700">{error}</div>
              </div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-2">
                Başlık <span className="text-red-500">*</span>
              </label>
              <Input
                id="title"
                name="title"
                type="text"
                value={formData.title}
                onChange={handleChange}
                required
                placeholder="Duyuru başlığını girin"
                className="w-full"
              />
            </div>

            <div>
              <label htmlFor="slug" className="block text-sm font-medium text-gray-700 mb-2">
                URL (Slug) <span className="text-red-500">*</span>
              </label>
              <Input
                id="slug"
                name="slug"
                type="text"
                value={formData.slug}
                onChange={handleChange}
                required
                placeholder="url-formatinda-metin"
                className="w-full"
              />
              <p className="mt-1 text-sm text-gray-500">
                Duyurunun URL'inde görünecek metin (örn: yeni-sistem-guncellemesi)
              </p>
            </div>
          </div>

          {/* Resim Yükleme Bölümü */}
          <div className="space-y-4">
            <label className="block text-sm font-medium text-gray-700">
              Duyuru Resmi
            </label>
            
            {/* Resim giriş tipi seçimi */}
            <div className="flex space-x-4 mb-4">
              <label className="flex items-center">
                <input
                  type="radio"
                  name="imageInputType"
                  value="url"
                  checked={imageInputType === "url"}
                  onChange={(e) => setImageInputType(e.target.value)}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">URL ile</span>
              </label>
              <label className="flex items-center">
                <input
                  type="radio"
                  name="imageInputType"
                  value="file"
                  checked={imageInputType === "file"}
                  onChange={(e) => setImageInputType(e.target.value)}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">Dosya yükle</span>
              </label>
            </div>

            {/* URL Girişi */}
            {imageInputType === "url" && (
              <div>
                <Input
                  name="imageUrl"
                  type="url"
                  value={formData.imageUrl}
                  onChange={handleChange}
                  placeholder="https://example.com/image.jpg"
                  className="w-full"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Resmin web adresini girin (HTTPS önerili)
                </p>
              </div>
            )}

            {/* Dosya Yükleme */}
            {imageInputType === "file" && (
              <div>
                <div className="flex items-center justify-center w-full">
                  <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100">
                    <div className="flex flex-col items-center justify-center pt-5 pb-6">
                      {isUploading ? (
                        <div className="flex items-center">
                          <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          <span className="text-sm text-gray-500">Yükleniyor...</span>
                        </div>
                      ) : (
                        <>
                          <svg className="w-8 h-8 mb-2 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                          </svg>
                          <p className="mb-2 text-sm text-gray-500">
                            <span className="font-semibold">Tıklayın</span> veya sürükleyin
                          </p>
                          <p className="text-xs text-gray-500">PNG, JPG veya WebP (MAX. 5MB)</p>
                        </>
                      )}
                    </div>
                    <input
                      type="file"
                      className="hidden"
                      accept="image/*"
                      onChange={handleFileUpload}
                      disabled={isUploading}
                    />
                  </label>
                </div>
              </div>
            )}

            {/* Resim Önizleme */}
            {previewImage && (
              <div className="relative">
                <div className="flex items-start space-x-4 p-4 bg-gray-50 rounded-lg">
                  <img
                    src={previewImage}
                    alt="Önizleme"
                    className="w-32 h-24 object-cover rounded-lg border"
                    onError={() => {
                      setError("Resim yüklenemedi. URL'yi kontrol edin.");
                      setPreviewImage("");
                    }}
                  />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-700">Resim Önizleme</p>
                    <p className="text-xs text-gray-500 mt-1 break-all">{previewImage}</p>
                    <button
                      type="button"
                      onClick={removeImage}
                      className="mt-2 text-xs text-red-600 hover:text-red-800"
                    >
                      🗑️ Resmi Kaldır
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div>
            <label htmlFor="content" className="block text-sm font-medium text-gray-700 mb-2">
              İçerik <span className="text-red-500">*</span>
            </label>
            <textarea
              id="content"
              name="content"
              rows={12}
              value={formData.content}
              onChange={handleChange}
              required
              placeholder="Duyuru içeriğini buraya yazın..."
              className="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-y"
            />
            <p className="mt-1 text-sm text-gray-500">
              Markdown formatını destekler
            </p>
          </div>

          <div className="flex items-center space-x-3 p-4 bg-gray-50 rounded-lg">
            <input
              id="published"
              name="published"
              type="checkbox"
              checked={formData.published}
              onChange={handleChange}
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="published" className="flex-1">
              <span className="block text-sm font-medium text-gray-700">
                🚀 Hemen Yayınla
              </span>
              <span className="block text-xs text-gray-500">
                Bu seçenek işaretliyse duyuru anında yayınlanır
              </span>
            </label>
          </div>

          <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
            <Button
              type="button"
              variant="outline"
              onClick={() => router.push("/admin/announcements")}
              disabled={isSubmitting}
              className="px-6"
            >
              İptal
            </Button>
            <Button 
              type="submit" 
              disabled={isSubmitting || isUploading}
              className="px-6 bg-blue-600 hover:bg-blue-700"
            >
              {isSubmitting ? (
                <span className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {announcement ? "Güncelleniyor..." : "Oluşturuluyor..."}
                </span>
              ) : (
                <span className="flex items-center">
                  {announcement ? "💾 Güncelle" : "✨ Oluştur"}
                </span>
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}