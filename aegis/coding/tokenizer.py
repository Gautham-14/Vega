"""Lexical retrieval terms and an optional pinned, model-native text tokenizer.

LLM serving owns chat templates, token IDs and vision processing. Aegis never
trains a replacement vocabulary or pretends image placeholders encode pixels.
"""
import hashlib
import re
import stat
from pathlib import Path


def get_tokens(text):
    """Identifier-aware lexical terms; these are not LLM vocabulary IDs."""
    if not isinstance(text, str):
        raise TypeError("Text must be a string")
    result = []
    for word in re.findall(r"\w+", text):
        result.append(word.casefold())
        if "_" not in word and not any(char.isupper() for char in word):
            continue
        split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", word)
        split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", split).replace("_", " ").split()
        result.extend(part.casefold() for part in split if part.casefold() != word.casefold())
    return result


class LocalModelTokenizer:
    """Read a reviewed tokenizer.json, never weights, remote code or a Hub ID.

    Matching the file hash does not prove it belongs to selected model weights.
    Chat templates and multimodal token counts remain the server's responsibility.
    """
    def __init__(self, tokenizer_file, sha256):
        path = Path(tokenizer_file)
        if (not isinstance(sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", sha256)
                or not path.is_absolute() or str(path).startswith(("\\\\", "//"))):
            raise ValueError("An absolute local tokenizer.json and SHA-256 pin are required")
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Tokenizer links and reparse points are not allowed")
        if path.name != "tokenizer.json" or not path.is_file() or path.stat().st_size > 64_000_000:
            raise ValueError("Use a tokenizer.json file no larger than 64 MB")
        with path.open("rb") as stream:
            raw = stream.read(64_000_001)
        if len(raw) > 64_000_000 or hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError("Tokenizer digest mismatch or size limit exceeded")
        from tokenizers import Tokenizer
        self._tokenizer = Tokenizer.from_str(raw.decode("utf-8"))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        self.sha256 = sha256

    def encode(self, text, *, add_special_tokens=False):
        if not isinstance(text, str) or len(text.encode("utf-8")) > 512_000:
            raise ValueError("Tokenizer input must be bounded UTF-8 text")
        return self._tokenizer.encode(text, add_special_tokens=add_special_tokens).ids

    def decode(self, ids, *, skip_special_tokens=False):
        if not isinstance(ids, list) or len(ids) > 512_000:
            raise ValueError("Token IDs must be a bounded list")
        if any(type(token) is not int or token < 0 or self._tokenizer.id_to_token(token) is None for token in ids):
            raise ValueError("Unknown token ID")
        return self._tokenizer.decode(ids, skip_special_tokens=skip_special_tokens)
