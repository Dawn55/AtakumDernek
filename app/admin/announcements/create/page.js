import AnnouncementForm from "../../../../components/forms/AnnouncementForm.js";
import Card from "../../../../components/ui/Card";

export default function CreateAnnouncementPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Yeni Duyuru Ekle</h1>
        <p className="text-gray-600 mt-2">
          Yeni bir duyuru oluşturun ve yayınlayın.
        </p>
      </div>

      <Card className="p-6">
        <AnnouncementForm />
      </Card>
    </div>
  );
}