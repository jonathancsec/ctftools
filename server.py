import json
import os
import re
import tempfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from crypto.autodecode import autodecode
from crypto.caesarshift import decrypt as decrypt_caesar
from crypto.caesarshift import decrypt_all as decrypt_caesar_all
from crypto.classical import (
    atbash,
    decode_a1z26,
    decode_bacon,
    decode_polybius,
    decrypt_affine,
    decrypt_beaufort,
    decrypt_bifid,
    decrypt_columnar,
    decrypt_playfair,
    decrypt_vigenere,
    rot47,
)
from crypto.encodings import DECODERS as ENCODING_DECODERS
from crypto.railfence import decrypt as decrypt_railfence
from forensics.analyzers import analyze_file


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_SIZE = 1_000_000
MAX_UPLOAD_SIZE = 25 * 1024 * 1024


def safe_filename(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "").name).strip("._")
    return (cleaned or "upload.bin")[:80]


class ToolRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Always serve the current files while editing the tools locally.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, status, payload):
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def read_json(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 1 or content_length > MAX_REQUEST_SIZE:
            raise ValueError("Request body must be between 1 byte and 1 MB.")
        request = json.loads(self.rfile.read(content_length).decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("Request body must be a JSON object.")
        return request

    def do_POST(self):
        route = urlparse(self.path).path
        if route == "/api/decode":
            self.handle_decode()
        elif route == "/api/autodecode":
            self.handle_autodecode()
        elif route == "/api/forensics":
            self.handle_forensics()
        else:
            self.send_json(404, {"error": "Unknown endpoint."})

    def handle_decode(self):
        try:
            request = self.read_json()

            cipher = request.get("cipher")
            text = request.get("text")
            if not isinstance(text, str):
                raise ValueError("Text must be a string.")

            if cipher == "caesar":
                if request.get("all_shifts") is True:
                    candidates = decrypt_caesar_all(text)
                    self.send_json(200, {
                        "results": [
                            {"shift": shift, "text": candidate}
                            for shift, candidate in enumerate(candidates)
                        ]
                    })
                    return

                shift = request.get("shift")
                if isinstance(shift, bool) or not isinstance(shift, int):
                    raise ValueError("Shift must be an integer.")
                result = decrypt_caesar(text, shift)
            elif cipher == "railfence":
                rails = request.get("rails")
                if isinstance(rails, bool) or not isinstance(rails, int):
                    raise ValueError("Number of rails must be an integer.")
                result = decrypt_railfence(text, rails)
            elif cipher == "atbash":
                result = atbash(text)
            elif cipher == "rot47":
                result = rot47(text)
            elif cipher == "bacon":
                result = decode_bacon(text)
            elif cipher == "a1z26":
                result = decode_a1z26(text)
            elif cipher == "vigenere":
                key = request.get("key")
                if not isinstance(key, str):
                    raise ValueError("Vigenère needs an alphabetic key.")
                result = decrypt_vigenere(text, key)
            elif cipher == "columnar":
                key = request.get("key")
                if not isinstance(key, str):
                    raise ValueError("Columnar transposition needs a keyword.")
                result = decrypt_columnar(text, key)
            elif cipher == "beaufort":
                key = request.get("key")
                if not isinstance(key, str):
                    raise ValueError("Beaufort needs an alphabetic key.")
                result = decrypt_beaufort(text, key)
            elif cipher == "bifid":
                key = request.get("key")
                if not isinstance(key, str):
                    raise ValueError("Bifid needs an alphabetic key.")
                period = request.get("period", 5)
                if isinstance(period, bool) or not isinstance(period, int):
                    raise ValueError("The Bifid period must be an integer.")
                result = decrypt_bifid(text, key, period)
            elif cipher == "playfair":
                key = request.get("key")
                if not isinstance(key, str):
                    raise ValueError("Playfair needs an alphabetic key.")
                result = decrypt_playfair(text, key)
            elif cipher == "polybius":
                result = decode_polybius(text)
            elif cipher == "affine":
                multiplier = request.get("a")
                offset = request.get("b")
                if isinstance(multiplier, bool) or not isinstance(multiplier, int):
                    raise ValueError("Affine multiplier must be an integer.")
                if isinstance(offset, bool) or not isinstance(offset, int):
                    raise ValueError("Affine offset must be an integer.")
                result = decrypt_affine(text, multiplier, offset)
            elif cipher in ENCODING_DECODERS:
                result = ENCODING_DECODERS[cipher](text)
            else:
                raise ValueError("Choose a supported cipher.")

            self.send_json(200, {"text": result})
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            self.send_json(400, {"error": str(error) or "Invalid request."})

    def handle_autodecode(self):
        try:
            request = self.read_json()
            text = request.get("text")
            if not isinstance(text, str):
                raise ValueError("Text must be a string.")
            self.send_json(200, {"results": autodecode(text)})
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            self.send_json(400, {"error": str(error) or "Invalid request."})

    def handle_forensics(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        if content_length < 1:
            self.send_json(400, {"error": "Choose a file to analyze."})
            return
        if content_length > MAX_UPLOAD_SIZE:
            self.send_json(413, {"error": "That file is larger than 25 MB."})
            return

        data = self.rfile.read(content_length)
        if not data:
            self.send_json(400, {"error": "The upload was empty."})
            return

        query = parse_qs(urlparse(self.path).query)
        name = safe_filename(query.get("name", ["upload.bin"])[0])

        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / name
                path.write_bytes(data)
                report = analyze_file(path, data, name)
        except Exception as error:
            self.send_json(500, {"error": f"Analysis failed: {error}"})
            return

        self.send_json(200, report)


def main():
    port = int(os.environ.get("PORT", "8000"))
    handler = partial(ToolRequestHandler, directory=str(ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"CTF Tools running at http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
