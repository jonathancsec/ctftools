import io
import zipfile

import pytest
from PIL import Image, PngImagePlugin

from app import create_app


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        DATA_DIR=tmp_path,
        UPLOAD_DIR=tmp_path / "uploads",
        ARTIFACT_DIR=tmp_path / "artifacts",
        DATABASE=tmp_path / "test.db",
        QUEUE_MODE="sync",
        TESTING=True,
    )
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def png_bytes():
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "flag{fixture_png}")
    buffer = io.BytesIO()
    Image.new("RGBA", (24, 24), (10, 20, 30, 255)).save(buffer, "PNG", pnginfo=info)
    return buffer.getvalue()


@pytest.fixture()
def zip_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("flag.txt", "flag{fixture_zip}")
    return buffer.getvalue()


@pytest.fixture()
def pcap_bytes():
    # Classic pcap global header (little endian) with no packets.
    return bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")


@pytest.fixture()
def png_with_zip(png_bytes, zip_bytes):
    return png_bytes + zip_bytes
