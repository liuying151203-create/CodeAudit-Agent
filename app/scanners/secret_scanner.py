from app.scanners.builtin_rules import scan_text


def scan_secrets(file_path: str, text: str):
    return [finding for finding in scan_text(file_path, text) if finding.category == "Secrets"]
