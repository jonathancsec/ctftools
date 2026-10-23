FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    DATA_DIR=/data

# Tools are installed at build time; jobs never install packages at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        binwalk \
        ca-certificates \
        file \
        libimage-exiftool-perl \
        sleuthkit \
        steghide \
        tshark \
        vim-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY workbench/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY workbench ./

RUN useradd --create-home --uid 10001 analyst \
    && mkdir -p /data \
    && chown -R analyst:analyst /app /data

USER analyst

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "180", "app:create_app()"]
