"use server";

import { prisma } from "@/lib/prisma";
import { revalidatePath } from "next/cache";
import { writeFile, mkdir } from "fs/promises";
import path from "path";

// Dosya yükleme fonksiyonu
export async function uploadFile(file) {
  if (!file) return null;

  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);

  // Upload klasörünü oluştur
  const uploadDir = path.join(process.cwd(), "public", "uploads", "documents");
  await mkdir(uploadDir, { recursive: true });

  // Dosya adını unique yap
  const fileName = `${Date.now()}-${file.name}`;
  const filePath = path.join(uploadDir, fileName);

  await writeFile(filePath, buffer);
  
  return {
    fileName: file.name,
    fileUrl: `/uploads/documents/${fileName}`,
    fileSize: buffer.length,
    mimeType: file.type
  };
}

// Yeni döküman oluştur
export async function createDocument(formData) {
  try {
    const title = formData.get("title");
    const description = formData.get("description");
    const category = formData.get("category");
    const published = formData.get("published") === "on";
    const file = formData.get("file");

    if (!title || !file) {
      throw new Error("Başlık ve dosya gereklidir");
    }

    const uploadResult = await uploadFile(file);
    
    if (!uploadResult) {
      throw new Error("Dosya yüklenemedi");
    }

    const document = await prisma.document.create({
      data: {
        title,
        description: description || "",
        category: category || "",
        published,
        fileName: uploadResult.fileName,
        fileUrl: uploadResult.fileUrl,
        fileSize: uploadResult.fileSize,
        mimeType: uploadResult.mimeType
      }
    });

    revalidatePath("/admin/documents");
    return { success: true, document };
  } catch (error) {
    console.error("Döküman oluşturma hatası:", error);
    return { success: false, error: error.message };
  }
}

// Döküman güncelle
export async function updateDocument(documentId, formData) {
  try {
    const title = formData.get("title");
    const description = formData.get("description");
    const category = formData.get("category");
    const published = formData.get("published") === "on";
    const file = formData.get("file");

    if (!title) {
      throw new Error("Başlık gereklidir");
    }

    const updateData = {
      title,
      description: description || "",
      category: category || "",
      published
    };

    // Eğer yeni dosya yüklendiyse
    if (file && file.size > 0) {
      const uploadResult = await uploadFile(file);
      if (uploadResult) {
        updateData.fileName = uploadResult.fileName;
        updateData.fileUrl = uploadResult.fileUrl;
        updateData.fileSize = uploadResult.fileSize;
        updateData.mimeType = uploadResult.mimeType;
      }
    }

    const document = await prisma.document.update({
      where: { id: documentId },
      data: updateData
    });

    revalidatePath("/admin/documents");
    return { success: true, document };
  } catch (error) {
    console.error("Döküman güncelleme hatası:", error);
    return { success: false, error: error.message };
  }
}

// Döküman sil
export async function deleteDocument(documentId) {
  try {
    await prisma.document.delete({
      where: { id: documentId }
    });

    revalidatePath("/admin/documents");
    return { success: true };
  } catch (error) {
    console.error("Döküman silme hatası:", error);
    return { success: false, error: error.message };
  }
}

// Tüm dökümanları getir
export async function getDocuments(published = null) {
  try {
    const where = published !== null ? { published } : {};
    
    const documents = await prisma.document.findMany({
      where,
      orderBy: { createdAt: "desc" }
    });

    return { success: true, documents };
  } catch (error) {
    console.error("Dökümanları getirme hatası:", error);
    return { success: false, error: error.message };
  }
}

// Tek döküman getir
export async function getDocument(documentId) {
  try {
    const document = await prisma.document.findUnique({
      where: { id: documentId }
    });

    if (!document) {
      throw new Error("Döküman bulunamadı");
    }

    return { success: true, document };
  } catch (error) {
    console.error("Döküman getirme hatası:", error);
    return { success: false, error: error.message };
  }
}