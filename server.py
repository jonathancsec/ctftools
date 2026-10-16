import json
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from crypto.caesarshift import decrypt as decrypt_caesar
from crypto.caesarshift import decrypt_all as decrypt_caesar_all
from crypto.railfence import decrypt as decrypt_railfence


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_SIZE = 1_000_000


class ToolRequestHandler(SimpleHTTPRequestHandler):
    def send_json(self, status, payload):
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self):
        if self.path != "/api/decode":
            self.send_json(404, {"error": "Unknown endpoint."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length < 1 or content_length > MAX_REQUEST_SIZE:
                raise ValueError("Request body must be between 1 byte and 1 MB.")
            request = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("Request body must be a JSON object.")

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
            else:
                raise ValueError("Choose a supported cipher.")

            self.send_json(200, {"text": result})
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            self.send_json(400, {"error": str(error) or "Invalid request."})


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