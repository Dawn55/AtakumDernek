import { NextResponse } from 'next/server';
import { writeFile, mkdir } from 'fs/promises';
import path from 'path';

export async function POST(request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file');

    if (!file) {
      return NextResponse.json(
        { error: 'Dosya bulunamadı' },
        { status: 400 }
      );
    }

    // Dosya tipini kontrol et
    if (!file.type.startsWith('image/')) {
      return NextResponse.json(
        { error: 'Sadece resim dosyaları kabul edilir' },
        { status: 400 }
      );
    }

    // Dosya boyutunu kontrol et (5MB limit)
    if (file.size > 5 * 1024 * 1024) {
      return NextResponse.json(
        { error: 'Dosya boyutu 5MB\'dan küçük olmalıdır' },
        { status: 400 }
      );
    }

    // Buffer'a çevir
    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);

    // Dosya adı ve uzantısını güvenli şekilde al
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 15);
    const originalName = file.name || 'upload.jpg';
    const fileExtension = path.extname(originalName) || '.jpg';
    const fileName = `${timestamp}-${randomString}${fileExtension}`;

    // Upload klasörünü oluştur
    const uploadDir = path.join(process.cwd(), 'public', 'uploads', 'announcements');
    await mkdir(uploadDir, { recursive: true });

    // Dosyayı kaydet
    const filePath = path.join(uploadDir, fileName);
    await writeFile(filePath, buffer);

    // URL'i döndür
    const fileUrl = `/uploads/announcements/${fileName}`;

    return NextResponse.json({
      success: true,
      url: fileUrl,
      filename: fileName
    });

  } catch (error) {
    console.error('Upload hatası:', error);
    return NextResponse.json(
      { error: error.message || 'Dosya yükleme sırasında hata oluştu' },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({ 
    message: 'API endpoint çalışıyor',
    timestamp: new Date().toISOString()
  });
}

