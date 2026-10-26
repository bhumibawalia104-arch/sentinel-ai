import os
from pathlib import Path
from uuid import uuid4

from huggingface_hub import InferenceClient


IMAGE_DIR = Path(__file__).resolve().parents[2] / "generated" / "images"

MODEL = "black-forest-labs/FLUX.1-schnell"


def generate_image(prompt: str) -> str:
    token = os.getenv("HF_TOKEN")

    if not token:
        raise RuntimeError("HF_TOKEN is not configured")

    IMAGE_DIR.mkdir(parents=True, exist_ok=True)

    client = InferenceClient(
        provider="auto",
        api_key=token,
        timeout=120
    )

    image = client.text_to_image(
        prompt=prompt,
        model=MODEL
    )

    filename = f"{uuid4().hex}.png"
    image_path = IMAGE_DIR / filename

    image.save(image_path)

    return f"/generated/images/{filename}"