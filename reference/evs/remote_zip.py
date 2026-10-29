"""Read members out of a remote zip archive with HTTP range requests, without downloading it whole.

The TS 26.444 conformance package is a single 1.84 GB zip on the 3GPP server, which serves one
connection slowly; the members a given stage of the port needs are a small fraction of it. This
reads the zip's central directory from the end of the file, then fetches only the requested members.

usage:
  remote_zip.py digest URL                    sha256 of the central directory (name, size, CRC-32
                                              of every member), the value fetch.sh pins
  remote_zip.py list URL                      one line per member: size, compressed size, name
  remote_zip.py get URL OUTDIR PATTERN...     extract the members matching any fnmatch PATTERN

Members are written atomically (`.tmp` then rename) and an existing file of the right size is left
alone, so an interrupted run resumes. `zipfile` checks each member's CRC-32 against the pinned
central directory as it extracts, so a member that changed or arrived damaged fails loudly.

Run with `python3 -I`: it imports only the standard library.
"""
import fnmatch
import hashlib
import http.client
import io
import os
import sys
import urllib.request
import zipfile

# The 3GPP file server sits behind a CDN that refuses requests without a browser-like agent.
HEADERS = {"User-Agent": "Mozilla/5.0"}
CHUNK = 4 << 20
ATTEMPTS = 8


class RemoteFile(io.RawIOBase):
    """A seekable, read-only view of a URL, backed by range requests and a single-chunk cache."""

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.position = 0
        request = urllib.request.Request(url, method="HEAD", headers=HEADERS)
        with urllib.request.urlopen(request, timeout=60) as response:
            self.size = int(response.headers["Content-Length"])
        self.cache_start = -1
        self.cache = b""

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self.position, 2: self.size}[whence]
        self.position = base + offset
        return self.position

    def _fetch(self, start, end):
        headers = dict(HEADERS, Range=f"bytes={start}-{end - 1}")
        for attempt in range(ATTEMPTS):
            try:
                request = urllib.request.Request(self.url, headers=headers)
                with urllib.request.urlopen(request, timeout=120) as response:
                    # The CDN occasionally ignores Range and answers 200 with the whole 1.8 GB
                    # archive; never read that body, just ask again.
                    if response.status != 206:
                        sys.stderr.write(f"retry {attempt}: status {response.status}, not 206\n")
                        continue
                    body = response.read()
                if len(body) == end - start:
                    return body
                sys.stderr.write(f"retry {attempt}: {len(body)} of {end - start} bytes\n")
            except (OSError, http.client.HTTPException) as error:
                sys.stderr.write(f"retry {attempt}: {error!r}\n")
        raise RuntimeError(f"range {start}-{end} failed after {ATTEMPTS} attempts")

    def read(self, count=-1):
        if count is None or count < 0:
            count = self.size - self.position
        count = min(count, self.size - self.position)
        if count <= 0:
            return b""
        start, end = self.position, self.position + count
        if not (self.cache_start <= start and end <= self.cache_start + len(self.cache)):
            self.cache = self._fetch(start, min(self.size, start + max(count, CHUNK)))
            self.cache_start = start
        offset = start - self.cache_start
        data = self.cache[offset:offset + count]
        self.position += len(data)
        return data

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def digest(archive):
    lines = sorted(f"{info.filename}\t{info.file_size}\t{info.CRC:08x}" for info in archive.infolist())
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def extract(archive, outdir, patterns):
    for info in archive.infolist():
        if info.is_dir() or not any(fnmatch.fnmatch(info.filename, pattern) for pattern in patterns):
            continue
        name = os.path.normpath(info.filename)
        if name.startswith("..") or os.path.isabs(name):
            raise RuntimeError(f"refusing unsafe member name {info.filename!r}")
        target = os.path.join(outdir, name)
        if os.path.exists(target) and os.path.getsize(target) == info.file_size:
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(info) as source, open(target + ".tmp", "wb") as sink:
            while block := source.read(1 << 20):
                sink.write(block)
        os.replace(target + ".tmp", target)
        print(f"got {info.filename}", flush=True)


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("digest", "list", "get"):
        sys.exit(__doc__)
    command, url = sys.argv[1], sys.argv[2]
    archive = zipfile.ZipFile(RemoteFile(url))
    if command == "digest":
        print(digest(archive))
    elif command == "list":
        for info in archive.infolist():
            print(f"{info.file_size:>12} {info.compress_size:>12} {info.filename}")
    else:
        extract(archive, sys.argv[3], sys.argv[4:])


if __name__ == "__main__":
    main()
