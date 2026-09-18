from flask import Flask, jsonify
from backend.agent.security_agent import analyze_scan, ask_agent
from pathlib import Path
import json,sqlite3,re,os,joblib
from datetime import datetime,timezone
from flask import request,send_from_directory
from flask_cors import CORS
from backend.ml.feature_extractor import extract_features,FEATURE_NAMES,explain_features

DB_PATH = "/tmp/phishguard.db"
ROOT=Path(__file__).resolve().parents[1]; ART=ROOT/'backend/ml/artifacts'; DB=ROOT/'backend/database/phishguard.db'; app=Flask(__name__); CORS(app)
model=joblib.load(ART/'model.joblib') if (ART/'model.joblib').exists() else None
def db():
 con=sqlite3.connect(DB); con.row_factory=sqlite3.Row; con.execute('CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT,prediction TEXT,risk_score INTEGER,risk_level TEXT,confidence REAL,reasons TEXT,features TEXT,created_at TEXT)'); con.commit(); return con
def valid(u):return isinstance(u,str) and len(u)<=2048 and bool(re.match(r'^(https?://)?[^\s/$.?#].[^\s]*$',u.strip(),re.I))
def score(f,p):
 s=round(p*70)+min(15,f['is_ip']*15)+min(8,f['has_at']*8)+min(8,f['is_shortener']*8)+min(8,f['has_suspicious_tld']*8)+min(8,f['has_punycode']*8)+min(7,f['num_subdomains']*2)+min(7,sum(f.get('kw_'+k,0) for k in ['login','verify','account','password','bank','signin','confirm']))+(5 if not f['is_https'] else 0)+(5 if f['url_length']>=100 else 0); return max(0,min(100,s))
def level(s):return 'low' if s<=30 else 'medium' if s<=60 else 'high'
def pred(p):return 'phishing' if p>=.55 else 'suspicious' if p>=.30 else 'legitimate'
@app.post('/api/scan')
def scan():
 d=request.get_json(silent=True) or {}; u=str(d.get('url','')).strip()
 if not valid(u):return jsonify(error='Please provide a valid HTTP/HTTPS URL.'),400
 if model is None:return jsonify(error='Model not trained. Run dataset download and training commands.'),503
 f=extract_features(u); p=float(model.predict_proba([[f[k] for k in FEATURE_NAMES]])[0][1]); pr=pred(p); rs=score(f,p); rl=level(rs); reasons=explain_features(f) or ['No major heuristic indicators were detected.']; con=db(); con.execute('INSERT INTO scans(url,prediction,risk_score,risk_level,confidence,reasons,features,created_at) VALUES(?,?,?,?,?,?,?,?)',(u,pr,rs,rl,max(p,1-p),json.dumps(reasons),json.dumps(f),datetime.now(timezone.utc).isoformat())); con.commit(); sid=con.execute('SELECT last_insert_rowid()').fetchone()[0]; con.close(); return jsonify(id=sid,url=u,prediction=pr,risk_score=rs,risk_level=rl,confidence=max(p,1-p),phishing_probability=p,reasons=reasons,features=f)
@app.get('/api/history')
def history():
 c=db(); rows=c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 200').fetchall(); c.close(); return jsonify([dict(r,reasons=json.loads(r['reasons']),features=json.loads(r['features'])) for r in rows])
@app.get('/api/statistics')
def stats():
 c=db(); rows=c.execute('SELECT prediction,risk_score FROM scans').fetchall(); c.close(); n=len(rows); return jsonify(total=n,safe=sum(x['prediction']=='legitimate' for x in rows),suspicious=sum(x['prediction']=='suspicious' for x in rows),phishing=sum(x['prediction']=='phishing' for x in rows),average_risk=round(sum(x['risk_score'] for x in rows)/n,1) if n else 0)
@app.get('/api/model-info')
def model_info():
 p=ART/'metrics.json'; return jsonify({'status':'ready','model':'Random Forest','features':len(FEATURE_NAMES),**json.loads(p.read_text())} if p.exists() else {'status':'not_trained'})
@app.route('/',defaults={'path':''})
@app.route('/<path:path>')
def frontend(path):
 return send_from_directory(ROOT/'frontend','index.html')

# ============================================================
# AI SECURITY ANALYST
# ============================================================

@app.route("/api/agent/chat", methods=["POST"])
def agent_chat():

    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "error": "Request data is required."
            }), 400

        question = str(
            data.get("question", "")
        ).strip()

        scan_data = data.get("scan", {})

        if not question:
            return jsonify({
                "success": False,
                "error": "Question is required."
            }), 400

        if len(question) > 1000:
            return jsonify({
                "success": False,
                "error": "Question is too long."
            }), 400

        answer = ask_agent(
            question,
            scan_data
        )

        return jsonify({
            "success": True,
            "answer": answer
        }), 200

    except RuntimeError as e:

        print("AI Configuration Error:", e)

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


    except Exception as e:

        import traceback

        print("\n========== AI AGENT ERROR ==========")

        print("ERROR:", str(e))

        traceback.print_exc()

        print("====================================\n")

        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


# ============================================================
# AI ANALYSIS
# ============================================================

@app.route("/api/agent/analyze", methods=["POST"])
def agent_analyze():

    try:

        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "error": "Scan data is required."
            }), 400

        analysis = analyze_scan(data)

        return jsonify({
            "success": True,
            "analysis": analysis
        }), 200

    except RuntimeError as e:

        print("AI Configuration Error:", e)

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


    except Exception as e:
        import traceback

        print("\n========== AI AGENT ERROR ==========")
        print("ERROR:", str(e))
        traceback.print_exc()
        print("====================================\n")

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
