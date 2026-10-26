from io import BytesIO
from pypdf import PdfReader
from docx import Document


def extract_document_text(filename: str, content: bytes) -> str:

    extension = filename.lower().rsplit(".", 1)[-1]

    if extension == "pdf":
        reader = PdfReader(BytesIO(content))
        text = "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

    elif extension == "docx":
        doc = Document(BytesIO(content))
        text = "\n".join(
            paragraph.text
            for paragraph in doc.paragraphs
        )

    elif extension == "txt":
        text = content.decode("utf-8")

    else:
        raise ValueError("Unsupported document type")

    return text