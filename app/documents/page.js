import { PrismaClient } from "@prisma/client";
import Card from "../../components/ui/Card";
import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'

const prisma = new PrismaClient();

export default async function DocumentsPage() {
  const documents = await prisma.document.findMany({
    where: { published: true },
    orderBy: { createdAt: "desc" }
  });

  const groupedDocuments = documents.reduce((acc, doc) => {
    const category = doc.category || "Genel";
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(doc);
    return acc;
  }, {});

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const getFileIcon = (mimeType) => {
    if (mimeType.includes("pdf")) return "📄";
    if (mimeType.includes("word")) return "📝";
    if (mimeType.includes("excel") || mimeType.includes("spreadsheet")) return "📊";
    if (mimeType.includes("image")) return "🖼️";
    if (mimeType.includes("zip") || mimeType.includes("rar")) return "📦";
    return "📁";
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <div className="relative bg-gradient-to-r from-green-600 to-blue-600 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl font-bold text-white mb-4">
              Belgeler
            </h1>
            <p className="text-xl text-green-100 max-w-2xl mx-auto">
              Atakum Bileşim Derneği'nin resmi belgelerine buradan ulaşabilirsiniz.
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {Object.entries(groupedDocuments).map(([category, docs]) => (
          <div key={category} className="mb-12">
            <h2 className="text-2xl font-bold text-gray-900 mb-6 border-b-2 border-gray-200 pb-2">
              {category}
            </h2>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {docs.map((document) => (
                <Card key={document.id} className="p-6 hover:shadow-lg transition-shadow duration-300">
                  <div className="flex items-start space-x-4">
                    <div className="text-2xl">
                      {getFileIcon(document.mimeType)}
                    </div>
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">
                        {document.title}
                      </h3>
                      {document.description && (
                        <p className="text-gray-600 mb-3 text-sm">
                          {document.description}
                        </p>
                      )}
                      <div className="flex items-center justify-between">
                        <div className="text-sm text-gray-500">
                          <span className="block">{formatFileSize(document.fileSize)}</span>
                          <span className="block">
                            {new Date(document.createdAt).toLocaleDateString("tr-TR")}
                          </span>
                        </div>
                        <a
                          href={document.fileUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors"
                        >
                          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                          </svg>
                          İndir
                        </a>
                      </div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          </div>
        ))}

        {documents.length === 0 && (
          <div className="text-center py-16">
            <div className="max-w-md mx-auto">
              <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-gray-900">Henüz belge bulunmamaktadır</h3>
              <p className="mt-2 text-gray-500">
                Yakında belgeler paylaşılacaktır.
              </p>
            </div>
          </div>
        )}
      </div>
      <Footer />
    </div>
  );
}