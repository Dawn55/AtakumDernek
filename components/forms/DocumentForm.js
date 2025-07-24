"use client";

import { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { createDocument, updateDocument } from "@/lib/actions/documents";
import Button from '@/components/ui/Button'
import Input from '@/components/ui/Input'

export default function DocumentForm({ document = null }) {
  const router = useRouter();
  const fileInputRef = useRef(null); // Dosya input'u için ref
  
  const [formData, setFormData] = useState({
    title: document?.title || "",
    description: document?.description || "",
    category: document?.category || "",
    published: document?.published || false,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError("");

    try {
      const formDataToSend = new FormData();
      formDataToSend.append("title", formData.title);
      formDataToSend.append("description", formData.description);
      formDataToSend.append("category", formData.category);
      
      if (formData.published) {
        formDataToSend.append("published", "on");
      }

      // Dosya input'unu ref ile al
      const selectedFile = fileInputRef.current?.files[0];
      
      // Yeni doküman oluştururken dosya zorunlu
      if (!document && !selectedFile) {
        setError("Lütfen bir dosya seçin.");
        setIsSubmitting(false);
        return;
      }

      // Dosya varsa ekle
      if (selectedFile) {
        formDataToSend.append("file", selectedFile);
      }

      let result;
      if (document) {
        result = await updateDocument(document.id, formDataToSend);
      } else {
        result = await createDocument(formDataToSend);
      }

      if (result.success) {
        router.push("/admin/documents");
        router.refresh();
      } else {
        setError(result.error || "Bir hata oluştu");
      }
    } catch (error) {
      console.error("Form gönderim hatası:", error);
      setError("Bir hata oluştu. Lütfen tekrar deneyin.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}

      <div>
        <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-2">
          Başlık
        </label>
        <Input
          id="title"
          name="title"
          type="text"
          value={formData.title}
          onChange={handleChange}
          required
          className="w-full"
        />
      </div>

      <div>
        <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-2">
          Açıklama
        </label>
        <textarea
          id="description"
          name="description"
          rows={4}
          value={formData.description}
          onChange={handleChange}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        />
      </div>

      <div>
        <label htmlFor="category" className="block text-sm font-medium text-gray-700 mb-2">
          Kategori
        </label>
        <Input
          id="category"
          name="category"
          type="text"
          value={formData.category}
          onChange={handleChange}
          placeholder="Örn: Tüzük, Yönetmelik, Rapor"
          className="w-full"
        />
      </div>

      <div>
        <label htmlFor="file" className="block text-sm font-medium text-gray-700 mb-2">
          Dosya {document ? "(Değiştirmek için yeni dosya seçin)" : ""}
        </label>
        <input
          id="file"
          name="file"
          type="file"
          ref={fileInputRef} // Ref eklendi
          required={!document} // Sadece yeni doküman için zorunlu
          accept=".pdf,.doc,.docx,.txt"
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        />
        {document && (
          <p className="mt-2 text-sm text-gray-600">
            Mevcut dosya: {document.fileName} ({document.mimeType})
          </p>
        )}
      </div>

      <div className="flex items-center">
        <input
          id="published"
          name="published"
          type="checkbox"
          checked={formData.published}
          onChange={handleChange}
          className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
        />
        <label htmlFor="published" className="ml-2 block text-sm text-gray-700">
          Yayınla
        </label>
      </div>

      <div className="flex justify-end space-x-4">
        <Button
          type="button"
          variant="outline"
          onClick={() => router.push("/admin/documents")}
          disabled={isSubmitting}
        >
          İptal
        </Button>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Kaydediliyor..." : document ? "Güncelle" : "Oluştur"}
        </Button>
      </div>
    </form>
  );
}