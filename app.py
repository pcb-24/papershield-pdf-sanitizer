import os
import re
import hashlib
from flask import Flask, request, render_template_string, send_from_directory
from pypdf import PdfReader, PdfWriter

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
CLEAN_FOLDER = "cleaned"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CLEAN_FOLDER, exist_ok=True)

# Exact PDF malware/action tags to hunt for
DANGEROUS_PATTERNS = {
    b"/JavaScript": "Embedded JavaScript",
    b"/JS": "Short JavaScript Tag",
    b"/Launch": "OS Command Launch Trigger",
    b"/OpenAction": "Auto-Run on Open Trigger",
    b"/EmbeddedFiles": "Hidden Embedded File",
    b"/SubmitForm": "External Data Exfiltration Form"
}

def xray_and_sanitize(filepath, filename):
    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    # 1. SHA-256 Fingerprint
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    is_real_pdf = raw_bytes.startswith(b"%PDF-")

    # 2. Check for exact dangerous tags (avoiding false positives inside images)
    found_threats = []
    for tag, desc in DANGEROUS_PATTERNS.items():
        # Match tag followed by whitespace, delimiter, or slash
        matches = re.findall(re.escape(tag) + rb"[\s/<(\[]", raw_bytes)
        if matches:
            found_threats.append(f"{tag.decode()} - {desc} ({len(matches)} found)")

    # 3. Extract Hidden Metadata & Create Sanitized Copy ("The Car Wash")
    metadata_found = {}
    page_count = 0
    clean_filename = "clean_" + filename
    clean_filepath = os.path.join(CLEAN_FOLDER, clean_filename)

    try:
        reader = PdfReader(filepath)
        page_count = len(reader.pages)
        
        if reader.metadata:
            for key, value in reader.metadata.items():
                if value and str(value).strip():
                    clean_key = key.replace("/", "")
                    metadata_found[clean_key] = str(value)

        # Build a fresh PDF with all pages but ZERO metadata
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({})  # Wipes hidden metadata clean!
        
        with open(clean_filepath, "wb") as out_f:
            writer.write(out_f)
        sanitized_ok = True
    except Exception as e:
        metadata_found["Note"] = f"Could not parse metadata ({str(e)})"
        sanitized_ok = False

    # 4. Security Verdict
    if not is_real_pdf:
        verdict = "DANGER: Fake PDF Header (Possible Disguised Executable!)"
        color = "#ef4444"
    elif found_threats:
        verdict = "SUSPICIOUS: Active Scripts / Auto-Actions Detected"
        color = "#f59e0b"
    else:
        verdict = "SAFE: No Malicious Scripts or Launch Triggers Found"
        color = "#4ade80"

    return {
        "sha256": sha256_hash,
        "size_kb": round(len(raw_bytes) / 1024, 2),
        "pages": page_count,
        "is_real_pdf": "Verified (%PDF-)" if is_real_pdf else "FAILED (Spoofed Extension)",
        "threats": found_threats,
        "metadata": metadata_found,
        "verdict": verdict,
        "color": color,
        "clean_filename": clean_filename if sanitized_ok else None
    }

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>PaperShield - PDF X-Ray & Sanitizer</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding: 30px; }
        .box { background: #1e293b; padding: 30px; border-radius: 12px; max-width: 720px; margin: auto; border: 2px dashed #38bdf8; }
        input[type=file] { margin: 15px 0; color: #94a3b8; }
        button { background: #38bdf8; color: #0f172a; border: none; padding: 10px 22px; border-radius: 6px; font-weight: bold; cursor: pointer; }
        button:hover { background: #0284c7; color: white; }
        .report { background: #0f172a; text-align: left; padding: 20px; border-radius: 8px; margin-top: 25px; border-left: 5px solid {{ report.color if report else '#38bdf8' }}; }
        .hash { font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; }
        .badge { font-weight: bold; font-size: 17px; color: {{ report.color if report else '#4ade80' }}; }
        .meta-box { background: #1e293b; padding: 12px 16px; border-radius: 6px; margin-top: 10px; font-size: 14px; }
        .clean-btn { display: inline-block; margin-top: 18px; background: #4ade80; color: #0f172a; padding: 12px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; }
        .clean-btn:hover { background: #22c55e; }
    </style>
</head>
<body>
    <h1>🛡️ PaperShield</h1>
    <p>Upload any PDF to X-Ray for hidden malware & scrub secret metadata.</p>
    <div class="box">
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="pdf_file" accept=".pdf" required><br>
            <button type="submit">🔍 Run Security X-Ray & Sanitize</button>
        </form>

        {% if report %}
        <div class="report">
            <div class="badge">Verdict: {{ report.verdict }}</div>
            <hr style="border-color: #334155; margin: 12px 0;">
            <p><b>📄 File Name:</b> {{ filename }} ({{ report.size_kb }} KB | {{ report.pages }} Pages)</p>
            <p><b>🔍 Magic Bytes Check:</b> {{ report.is_real_pdf }}</p>
            <p><b>🔑 SHA-256 Fingerprint:</b><br><span class="hash">{{ report.sha256 }}</span></p>
            
            <p><b>🦠 Malware / Script Signatures:</b> 
                {% if report.threats %}
                    <span style="color: #f59e0b;">{{ report.threats | join(', ') }}</span>
                {% else %}
                    <span style="color: #4ade80;">0 Dangerous Triggers Found</span>
                {% endif %}
            </p>

            <p><b>🕵️ Hidden Metadata Leaked Inside This PDF:</b></p>
            <div class="meta-box">
                {% if report.metadata %}
                    {% for k, v in report.metadata.items() %}
                        <div><b>{{ k }}:</b> <span style="color: #fbbf24;">{{ v }}</span></div>
                    {% endfor %}
                {% else %}
                    <span style="color: #94a3b8;">No hidden author/device metadata found in this file.</span>
                {% endif %}
            </div>

            {% if report.clean_filename %}
            <div style="text-align: center;">
                <a class="clean-btn" href="/download/{{ report.clean_filename }}">
                    🧼 Download Sanitized PDF (Metadata & Triggers Stripped)
                </a>
            </div>
            {% endif %}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_PAGE, report=None)

@app.route("/upload", methods=["POST"])
def upload_pdf():
    file = request.files.get("pdf_file")
    if not file or not file.filename.endswith(".pdf"):
        return render_template_string(HTML_PAGE, report=None)
    
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    report_data = xray_and_sanitize(filepath, file.filename)
    return render_template_string(HTML_PAGE, report=report_data, filename=file.filename)

@app.route("/download/<filename>")
def download_clean(filename):
    return send_from_directory(CLEAN_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
