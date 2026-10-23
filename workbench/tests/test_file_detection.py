from analyzer.file_detection import detect_file, detect_from_bytes, hash_file, scan_signatures


def test_png_is_detected_from_content(tmp_path, png_bytes):
    path = tmp_path / "upload.bin"
    path.write_bytes(png_bytes)

    info = detect_file(path, "upload.bin")

    assert info.type_label == "PNG image"
    assert info.mime == "image/png"
    assert info.is_image is True
    assert info.image_size == (24, 24)
    # The extension is reported for humans but never used for detection.
    assert info.extension == "bin"
    assert len(info.sha256) == 64
    assert info.sha256 == hash_file(path, "sha256")
    assert len(info.md5) == 32


def test_extension_never_decides_the_type(tmp_path, zip_bytes):
    path = tmp_path / "photo.png"
    path.write_bytes(zip_bytes)

    info = detect_file(path, "photo.png")

    assert info.type_label == "ZIP archive"
    assert info.mime == "application/zip"
    assert info.is_archive is True
    assert info.extension == "png"


def test_text_detection(tmp_path):
    path = tmp_path / "notes.dat"
    path.write_bytes(b"just some readable text\nwith two lines\n")

    info = detect_file(path, "notes.dat")

    assert info.type_label == "text file"
    assert info.mime == "text/plain"
    assert info.is_text is True


def test_pcap_detection(tmp_path, pcap_bytes):
    path = tmp_path / "capture.bin"
    path.write_bytes(pcap_bytes)

    info = detect_file(path, "capture.bin")

    assert info.is_pcap is True
    assert info.mime == "application/vnd.tcpdump.pcap"


def test_unknown_binary(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(bytes(range(256)) * 4)

    info = detect_file(path, "blob.bin")

    assert info.type_label == "unknown binary"
    assert info.mime == "application/octet-stream"


def test_embedded_signatures_are_listed(tmp_path, png_with_zip):
    path = tmp_path / "image.png"
    path.write_bytes(png_with_zip)

    hits, truncated = scan_signatures(path)

    labels = [label for _offset, label in hits]
    assert "PNG image" in labels
    assert "ZIP archive" in labels
    assert truncated is False
    offsets = [offset for offset, _label in hits]
    assert offsets == sorted(offsets)


def test_zip_metadata_is_not_reported_as_embedded_files(tmp_path, png_with_zip):
    path = tmp_path / "image.png"
    path.write_bytes(png_with_zip)

    hits, _truncated = scan_signatures(path)
    labels = [label for _offset, label in hits]

    assert labels.count("ZIP archive") == 1
    assert "ICO image" not in labels
    assert "Empty ZIP archive" not in labels


def test_detect_from_bytes_does_not_need_a_file():
    label, mime, kind = detect_from_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    assert label == "PNG image"
    assert mime == "image/png"
    assert kind == "image"
