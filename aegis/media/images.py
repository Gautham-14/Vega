"""Decode actual local image bytes, enforce limits, and remove ancillary metadata."""
import base64
import binascii
import hashlib
import io
import warnings

MAX_IMAGE_BYTES = 2_000_000
MAX_BASE64 = 4 * ((MAX_IMAGE_BYTES + 2) // 3)
MAX_PIXELS = 4_194_304


def sanitize(encoded):
    # Never interpret a string as a URL or a server filesystem path.
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= MAX_BASE64:
        raise ValueError("Image must be at most 2 MB of base64-encoded PNG, JPEG or WebP")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Image must contain base64 bytes, not a URL or file path") from None
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("Image exceeds 2 MB")
    try:
        from PIL import Image, ImageOps
    except ImportError:
        raise ValueError("Image decoding requires the local Pillow dependency; install requirements-media.txt") from None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw), formats=["PNG", "JPEG", "WEBP"]) as source:
                width, height = source.size
                if width < 1 or height < 1 or width * height > MAX_PIXELS or getattr(source, "n_frames", 1) != 1:
                    raise ValueError("Image exceeds pixel limits or contains animation")
                source.verify()
            with Image.open(io.BytesIO(raw), formats=["PNG", "JPEG", "WEBP"]) as source:
                oriented = ImageOps.exif_transpose(source)
                rgba = oriented.convert("RGBA")
                rgb = Image.new("RGB", rgba.size, "white")
                rgb.paste(rgba, mask=rgba.getchannel("A"))
                # A fresh image excludes EXIF, comments, ICC and textual metadata.
                clean = Image.frombytes("RGB", rgb.size, rgb.tobytes())
                output = io.BytesIO()
                clean.save(output, format="PNG")
                value = output.getvalue()
                width, height = clean.size
                clean.close()
                rgb.close()
                rgba.close()
                oriented.close()
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValueError("Image is malformed, animated or exceeds decoding limits") from None
    if len(value) > MAX_IMAGE_BYTES:
        raise ValueError("Decoded PNG exceeds 2 MB; provide a smaller image")
    return {"data": base64.b64encode(value).decode("ascii"), "mime_type": "image/png",
            "sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value), "width": width, "height": height}


def metadata(image):
    return {key: value for key, value in image.items() if key != "data"}
