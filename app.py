import os
import sys
import json
import logging
import traceback
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_cors import CORS


# ── Setup paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s — %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ── App ────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
app.secret_key = 'trust-advisor-secret-2024'

# ── Imports ────────────────────────────────────────────────────────────────────
from database.db import init_db, save_scan, get_scan, get_all_scans, update_report_path
from services.scraper import scrape, scrape_html_file
from analyzers.dark_patterns import analyze as analyze_dark
from analyzers.phishing import analyze as analyze_phishing
from analyzers.ai_analyzer import analyze as analyze_ai
from analyzers.scoring import compute as compute_score
from services.pdf_generator import generate as generate_pdf
from services.chatbot import respond as chatbot_respond

# ── Init DB ────────────────────────────────────────────────────────────────────
init_db()
logger.info("Database initialised")


# ── Helpers ────────────────────────────────────────────────────────────────────

def run_full_analysis(scraped: dict) -> dict:
    """Run all analysis engines on scraped data. Never raises."""
    try:
        dark_result = analyze_dark(scraped)
    except Exception:
        logger.error("Dark pattern analysis failed:\n" + traceback.format_exc())
        dark_result = {'dark_pattern_score': 0.0, 'dark_indicators': []}

    try:
        phish_result = analyze_phishing(scraped)
    except Exception:
        logger.error("Phishing analysis failed:\n" + traceback.format_exc())
        phish_result = {'phishing_score': 0.0, 'phishing_indicators': []}

    try:
        ai_result = analyze_ai(scraped)
    except Exception:
        logger.error("AI analysis failed:\n" + traceback.format_exc())
        ai_result = {'ai_risk_score': 0.0, 'ai_indicators': []}

    score_result = compute_score(
        dark_result['dark_pattern_score'],
        phish_result['phishing_score'],
        ai_result['ai_risk_score']
    )

    return {
        **dark_result,
        **phish_result,
        **ai_result,
        **score_result,
        'url': scraped.get('url', ''),
        'screenshot_path': scraped.get('screenshot_path', ''),
        'scan_status': scraped.get('status', 'ok'),
        'status_message': scraped.get('status_message', ''),
        'scrape_method': scraped.get('method', 'unknown'),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def scan():
    """Main scan endpoint."""
    try:
        data = request.get_json(force=True)
        url = (data.get('url') or '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        logger.info(f"Scanning: {url}")
        scraped = scrape(url)
        result = run_full_analysis(scraped)

        scan_id = save_scan(result)
        result['id'] = scan_id

        # Generate PDF in background (don't block response)
        try:
            pdf_path = generate_pdf(result)
            if pdf_path:
                update_report_path(scan_id, pdf_path)
                result['report_path'] = pdf_path
        except Exception:
            logger.warning("PDF generation failed (non-fatal)")

        logger.info(f"Scan complete: {url} — Score: {result['total_score']}, Verdict: {result['verdict']}")
        return jsonify(_serialize(result))

    except Exception:
        logger.error("Scan endpoint error:\n" + traceback.format_exc())
        return jsonify({'error': 'Internal server error. Please try again.'}), 500

@app.route('/api/screenshot/<int:scan_id>')
def get_screenshot(scan_id):
    try:
        scan = get_scan(scan_id)
        if not scan:
            print("No scan found")
            abort(404)

        ss_path = scan.get('screenshot_path')
        print("DB screenshot path:", ss_path)

        if not ss_path:
            print("No screenshot path in DB")
            abort(404)

        # Convert "static/screenshots/file.png"
        # into absolute path
        full_path = os.path.join(os.getcwd(), ss_path)
        print("Full path:", full_path)

        if not os.path.exists(full_path):
            print("File does not exist!")
            abort(404)

        return send_file(full_path, mimetype='image/png')

    except Exception as e:
        print("Screenshot route error:", e)
        abort(404)

@app.route('/api/history')
def history():
    try:
        scans = get_all_scans(limit=50)
        return jsonify([_serialize(s) for s in scans])
    except Exception:
        return jsonify([])


@app.route('/api/scan/<int:scan_id>')
def get_scan_result(scan_id):
    try:
        scan = get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(_serialize(scan))
    except Exception:
        return jsonify({'error': 'Error fetching scan'}), 500


@app.route('/api/report/<int:scan_id>')
def download_report(scan_id):
    try:
        scan = get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        report_path = scan.get('report_path', '')
        if not report_path or not os.path.exists(report_path):
            # Generate on demand
            pdf_path = generate_pdf(scan)
            if not pdf_path or not os.path.exists(pdf_path):
                return jsonify({'error': 'Report generation failed'}), 500
            update_report_path(scan_id, pdf_path)
            report_path = pdf_path

        url_safe = scan.get('url', 'report').replace('https://', '').replace('http://', '').replace('/', '_')[:30]
        fname = f"trust_report_{url_safe}.pdf"
        return send_file(report_path, as_attachment=True, download_name=fname, mimetype='application/pdf')
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Download failed'}), 500



@app.route('/api/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.get_json(force=True)
        message = data.get('message', '')
        scan_id = data.get('scan_id')
        context = {}
        if scan_id:
            scan = get_scan(int(scan_id))
            if scan:
                context = scan
        reply = chatbot_respond(message, context)
        return jsonify({'reply': reply})
    except Exception:
        return jsonify({'reply': 'Sorry, I encountered an error. Please try again.'})


@app.route('/demo-test')
def demo_test():
    return render_template('demo.html')


@app.route('/api/demo/<demo_type>', methods=['POST'])
def run_demo(demo_type):
    """Run analysis on a built-in demo HTML page."""
    try:
        demo_pages = {
            'dark': 'dark_pattern_demo.html',
            'phishing': 'phishing_demo.html',
            'safe': 'safe_demo.html',
        }
        fname = demo_pages.get(demo_type)
        if not fname:
            return jsonify({'error': 'Invalid demo type'}), 400

        demo_path = os.path.join(BASE_DIR, 'demo_test_pages', fname)
        with open(demo_path, 'r', encoding='utf-8') as f:
            html_content = f.read()

        url_map = {
            'dark': 'demo://dark-pattern-showcase',
            'phishing': 'http://paypal-secure-verify.tk/login',
            'safe': 'https://mozilla.org',
        }
        scraped = scrape_html_file(html_content, url=url_map.get(demo_type, 'demo://test'))
        result = run_full_analysis(scraped)

        scan_id = save_scan(result)
        result['id'] = scan_id

        try:
            pdf_path = generate_pdf(result)
            if pdf_path:
                update_report_path(scan_id, pdf_path)
                result['report_path'] = pdf_path
        except Exception:
            pass

        return jsonify(_serialize(result))
    except Exception:
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Demo failed'}), 500


@app.route('/api/stats')
def stats():
    try:
        scans = get_all_scans(limit=500)
        total = len(scans)
        safe = sum(1 for s in scans if s.get('verdict') == 'SAFE')
        caution = sum(1 for s in scans if s.get('verdict') == 'CAUTION')
        avoid = sum(1 for s in scans if s.get('verdict') == 'AVOID')
        avg_score = round(sum(s.get('total_score', 0) for s in scans) / total, 1) if total else 0
        return jsonify({
            'total': total, 'safe': safe, 'caution': caution,
            'avoid': avoid, 'avg_score': avg_score
        })
    except Exception:
        return jsonify({'total': 0, 'safe': 0, 'caution': 0, 'avoid': 0, 'avg_score': 0})


def _serialize(d: dict) -> dict:
    """Ensure all values are JSON-serialisable."""
    out = {}
    for k, v in d.items():
        if k == 'soup':
            continue
        if isinstance(v, list):
            out[k] = v
        elif isinstance(v, (int, float, bool, str)) or v is None:
            out[k] = v
        else:
            out[k] = str(v)
    return out


if __name__ == '__main__':
    logger.info("Starting AI Website Trust Advisor...")
    logger.info("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)