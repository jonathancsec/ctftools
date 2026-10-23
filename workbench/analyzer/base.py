"""Shared types for the analysis pipeline.

Each tool module returns a ToolResult, so the dispatcher, the database and the
report exporter never need to know how a tool actually runs.
"""

from dataclasses import dataclass, field
from pathlib import Path


TOOL_STATUSES = {"completed", "empty", "skipped", "failed", "unavailable"}


def human_size(size):
    if size is None:
        return "unknown"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


@dataclass(frozen=True)
class FileInfo:
    path: Path
    original_name: str
    size: int
    sha256: str
    md5: str
    extension: str
    type_label: str
    mime: str
    is_text: bool
    is_image: bool
    is_archive: bool
    is_pcap: bool
    is_disk_image: bool
    image_format: str | None = None
    image_size: tuple | None = None
    image_mode: str | None = None

    @property
    def display_size(self):
        return human_size(self.size)


@dataclass(frozen=True)
class ToolSpec:
    key: str
    display_name: str
    binary: str | None = None
    version_args: tuple = ("--version",)
    timeout: int = 60
    install_hint: str = ""


@dataclass
class ToolResult:
    status: str = "completed"
    summary: str = ""
    output: str = ""
    error: str = ""
    version: str = ""
    duration_ms: int = 0
    artifacts: list = field(default_factory=list)

    def __post_init__(self):
        if self.status not in TOOL_STATUSES:
            raise ValueError(f"Unknown tool status: {self.status}")


@dataclass
class AnalysisContext:
    job_id: str
    file_info: FileInfo
    artifacts_root: Path
    timeout: int = 60
    output_limit: int = 100_000
    max_string_lines: int = 500
    max_artifact_bytes: int = 5 * 1024 * 1024
    # Supplied per job for steghide only; never persisted or reported.
    passphrase: str | None = None

    def artifact_dir(self, tool_key):
        directory = self.artifacts_root / self.job_id / tool_key
        directory.mkdir(parents=True, exist_ok=True)
        return directory
