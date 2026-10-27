# 🛡️ PaperShield — PDF Malware X-Ray & Metadata Sanitizer

A cybersecurity web application built with **Python, Flask, and PyPDF** that inspects PDF files for hidden malware triggers, verifies cryptographic file integrity (SHA-256), reveals leaked author/device metadata, and generates a sanitized copy with one click.

## 🚀 Real-World Problem Solved
1. **Malicious PDF Booby Traps:** Attackers embed auto-executing tags (`/JavaScript`, `/Launch`, `/OpenAction`) inside research papers, resumes, and notes, or disguise executables using spoofed extensions.
2. **Metadata Privacy Leaks:** PDFs silently leak the creator's software/OS (`Chromium`, `Skia/PDF`), author names, and exact creation timestamps.

## 🔒 Cybersecurity Concepts Covered
* **Cryptographic Integrity (CIA Triad):** Computes the **SHA-256** hash of every uploaded document.
* **Magic Byte Verification:** Inspects raw file headers (`%PDF-`) to catch spoofed file extensions.
* **Static Malware Analysis:** Scans raw binary streams for dangerous PDF specification triggers (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, `/EmbeddedFiles`, `/SubmitForm`).
* **Privacy & Anti-Forensics ("The Car Wash"):** Rebuilds the PDF page-by-page with `pypdf`, stripping 100% of hidden document metadata.

## 🛠️ How to Run Locally
1. Install dependencies: `pip3 install flask pypdf`
2. Run the server: `python3 app.py`
3. Open `http://127.0.0.1:5000` in your browser.
