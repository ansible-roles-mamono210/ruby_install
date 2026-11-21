"""Validate a verified Ruby source archive before writing its members on target."""
import gzip
import hashlib
import math
import os
import shutil
import tarfile
import tempfile

from .state import Stop, trusted_file


BLOCK = 128 * 1024
MAX_TAR = 384 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
KINDS = {tarfile.REGTYPE: "file", tarfile.AREGTYPE: "file", tarfile.DIRTYPE: "directory",
         tarfile.SYMTYPE: "symlink", tarfile.LNKTYPE: "hardlink"}


def require(condition, message):
    if not condition:
        raise Stop("SOURCE_ARCHIVE_INVALID: " + message)


def valid_name(value):
    return bool(value) and len(value) <= 1024 and not value.startswith("/") and "\\" not in value and value.isprintable()


def archive_members(tar, size, root):
    nodes = {}
    directories = {root}
    for member in tar:
        name = member.name
        parts = name.split("/")
        require(len(nodes) < 30000 and name not in nodes and valid_name(name)
                and parts[0] == root and all(p not in ("", ".", "..") for p in parts), "invalid member path or count")
        kind = KINDS.get(member.type)
        require(kind and not member.mode & 0o6000 and not member.sparse and
                not any(k.startswith("GNU.sparse") for k in member.pax_headers), "unsupported archive member")
        require(0 <= member.size <= MAX_FILE and (kind == "file" or not member.size)
                and member.offset_data + member.size <= size
                and math.isfinite(member.mtime) and 0 <= member.mtime <= 4102444800, "invalid member metadata")
        require(name != root or kind == "directory", "expected a source directory")
        nodes[name] = member
        directories.update("/".join(parts[:n]) for n in range(1, len(parts)))
        if kind == "directory":
            directories.add(name)
    require(all(d not in nodes or nodes[d].isdir() for d in directories), "member below a non-directory")
    for name in ("configure", "configure.ac", "version.h"):
        item = nodes.get(root + "/" + name)
        require(item and item.isreg() and item.size, "required source file is missing")

    for name, member in nodes.items():
        if member.islnk():
            target = nodes.get(member.linkname)
            require(target and target.isreg(), "hard link must name an archived regular file")
        elif member.issym():
            # Resolve each component before '..', including any intervening link.
            resolved = []
            pending = list(reversed(name.split("/")))
            hops = 0
            while pending:
                part = pending.pop()
                if part in ("", "."):
                    continue
                if part == "..":
                    require(len(resolved) > 1, "symbolic link leaves source directory")
                    resolved.pop()
                    continue
                resolved.append(part)
                current = "/".join(resolved)
                entry = nodes.get(current)
                if entry and (entry.issym() or entry.islnk()):
                    hops += 1
                    require(hops <= 40 and valid_name(entry.linkname), "invalid symbolic link")
                    resolved = resolved[:-1] if entry.issym() else []
                    pending.extend(reversed(entry.linkname.split("/")))
                elif pending:
                    require(current in directories, "symbolic link traverses a non-directory")
            require("/".join(resolved) in nodes or "/".join(resolved) in directories, "dangling symbolic link")
    return nodes


def extract(work, version, expected_digest):
    archive = work / "source.tar.gz"
    root = "ruby-" + version
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as blob:
        require(trusted_file(os.fstat(blob.fileno())), "source is not a trusted regular file")
        sha = hashlib.sha256()
        for chunk in iter(lambda: blob.read(BLOCK), b""):
            sha.update(chunk)
        if sha.hexdigest() != expected_digest:
            raise Stop("SOURCE_CHECKSUM_MISMATCH: source changed before extraction")
        blob.seek(0)
        # Validate gzip CRC and bound even discarded metadata/padding. A plain
        # seekable file also avoids decompressing once per member during extraction.
        with tempfile.TemporaryFile(dir=work) as plain, gzip.GzipFile(fileobj=blob, mode="rb") as gz:
            for chunk in iter(lambda: gz.read(BLOCK), b""):
                require(plain.tell() + len(chunk) <= MAX_TAR, "source exceeds the expansion limit")
                plain.write(chunk)
            size = plain.tell()
            require(size > 0 and size % 512 == 0, "truncated tar block")
            plain.seek(0)
            with tarfile.open(fileobj=plain, mode="r:", encoding="utf-8", errors="strict") as tar:
                nodes = archive_members(tar, size, root)
                require(tar.offset <= size, "truncated final member")
                plain.seek(tar.offset)
                require(all(not chunk.strip(b"\0") for chunk in iter(lambda: plain.read(BLOCK), b"")),
                        "unexpected data after the final member")
                destination = work / "source"
                destination.mkdir(mode=0o700)
                for name, member in nodes.items():
                    path = destination / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if member.isdir():
                        path.mkdir(exist_ok=True)
                    elif member.isreg():
                        with tar.extractfile(member) as inp, path.open("xb") as out:
                            shutil.copyfileobj(inp, out, length=BLOCK)
                        path.chmod(0o755 if member.mode & 0o111 else 0o644)
                        os.utime(path, (member.mtime, member.mtime))
                # All writes to regular files are finished before creating any link.
                for name, member in nodes.items():
                    if member.islnk():
                        os.link(destination / member.linkname, destination / name)
                    elif member.issym():
                        (destination / name).symlink_to(member.linkname)
    return destination / root
