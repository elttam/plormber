def open_read(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()