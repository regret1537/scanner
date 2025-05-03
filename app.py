from flask import Flask, render_template, request
from scanners.sql_injection import scan_sql_injection
from scanners.xss import scan_xss

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form.get('url').strip()
        # 依序執行各類掃描
        results = {
            'SQL Injection': scan_sql_injection(target),
            'XSS': scan_xss(target),
        }
        return render_template('result.html', target=target, results=results)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
