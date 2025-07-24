import { PrismaClient } from "@prisma/client";
import { notFound } from "next/navigation";
import DocumentForm from "../../../../../components/forms/DocumentForm";
import Card from "../../../../../components/ui/Card";

const prisma = new PrismaClient();

export default async function EditDocumentPage({ params }) {
  const document = await prisma.document.findUnique({
    where: { id: params.id }
  });

  if (!document) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Belge Düzenle</h1>
        <p className="text-gray-600 mt-2">
          "{document.title}" belgesini düzenleyin.
        </p>
      </div>

      <Card className="p-6">
        <DocumentForm document={document} />
      </Card>
    </div>
  );
}