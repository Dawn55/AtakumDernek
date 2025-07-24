import DocumentForm from "../../../../components/forms/DocumentForm";
import Card from "../../../../components/ui/Card";

export default function CreateDocumentPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Yeni Belge Ekle</h1>
        <p className="text-gray-600 mt-2">
          Yeni bir belge yükleyin ve yayınlayın.
        </p>
      </div>

      <Card className="p-6">
        <DocumentForm />
      </Card>
    </div>
  );
}