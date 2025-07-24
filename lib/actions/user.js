// lib/actions/user.js
'use server';

import { PrismaClient } from '@prisma/client';
import { revalidatePath } from 'next/cache';

const prisma = new PrismaClient();

export async function updateUser(userId, formData) {
  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        name: formData.name,
        email: formData.email,
        role: parseInt(formData.role),
        updatedAt: new Date(),
      },
    });
    
    // Cache'i yenile
    revalidatePath('/admin/users');
    
    await prisma.$disconnect();
    return { success: true, user: updatedUser };
  } catch (error) {
    console.error('User update error:', error);
    await prisma.$disconnect();
    
    // Prisma error kodlarına göre özel mesajlar
    if (error.code === 'P2002') {
      return { success: false, error: 'Bu e-posta adresi zaten kullanılıyor.' };
    }
    
    return { success: false, error: 'Güncelleme işlemi başarısız oldu.' };
  }
}