from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


OUTPUT_DIR = Path(__file__).resolve().parents[1] / "demo_dataset"


def create_document(filename, applicant_name, date_of_birth, altered=False):
    output_path = OUTPUT_DIR / filename
    page = canvas.Canvas(str(output_path), pagesize=A4)
    page_height = A4[1]

    page.setFont("Helvetica-Bold", 18)
    page.drawString(54, page_height - 58, "SYNTHETIC DOCUMENT - DEMO ONLY")
    page.setFont("Helvetica-Bold", 14)
    page.drawString(54, page_height - 98, "Sample Identity Declaration")

    lines = [
        ("Document Type", "Identity declaration"),
        ("Applicant Name", applicant_name),
        ("Date of Birth", date_of_birth),
        ("Mobile Number", "9000000000"),
        ("Address", "1 Example Street, Sample City"),
        ("Reference Number", "DEMO-0001")
    ]

    y = page_height - 145
    for label, value in lines:
        page.setFont("Helvetica", 11)
        page.drawString(60, y, f"{label}:")
        if altered and label == "Date of Birth":
            page.setFont("Helvetica-Bold", 30)
        else:
            page.setFont("Helvetica", 11)
        page.drawString(190, y, value)
        y -= 34

    page.setFont("Helvetica-Oblique", 8)
    page.drawString(
        54,
        36,
        "Entirely fictional test data. Not an identity document. Do not use for verification."
    )
    page.showPage()
    page.save()
    return output_path


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    created = [
        create_document(
            "application_record.pdf",
            "Asha Example",
            "01/01/1990"
        ),
        create_document(
            "supporting_record.pdf",
            "Asha Example",
            "01/01/1990"
        ),
        create_document(
            "altered_supporting_record.pdf",
            "Asha Example",
            "01/01/1991",
            altered=True
        )
    ]

    for path in created:
        print(path)


if __name__ == "__main__":
    main()
