"""SelfSameAi demo server.   Run:  python server.py   then open http://127.0.0.1:5000"""
import random
import threading
from flask import Flask, jsonify, request, send_from_directory

from core.scenarios import SCENARIOS, build, AGENTS
from core.contracts import load_contracts
from core import evaluate

app = Flask(__name__, static_folder="static")
app.json.sort_keys = False   # keep scenario order stable in the UI
lock = threading.Lock()
state = {"gw": build(seed=1), "eval": None, "eval_running": False}


def _compute_eval():
    state["eval_running"] = True
    try:
        state["eval"] = evaluate.run_all()
    finally:
        state["eval_running"] = False


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/meta")
def meta():
    c = load_contracts()
    return jsonify({
        "scenarios": [{"key": k, "title": v[0], "attack": v[2]} for k, v in SCENARIOS.items()],
        "contracts": {k: v.model_dump() for k, v in c.items()},
        "agents": AGENTS,
    })


@app.get("/api/state")
def get_state():
    with lock:
        return jsonify(state["gw"].snapshot())


@app.post("/api/run")
def run():
    key = request.json["scenario"]
    with lock:
        SCENARIOS[key][1](state["gw"], random.Random())
        return jsonify(state["gw"].snapshot())


@app.post("/api/reset")
def reset():
    enforce = bool(request.json.get("enforce", True)) if request.is_json else True
    with lock:
        state["gw"] = build(seed=random.randint(1, 10_000), enforce=enforce)
        return jsonify(state["gw"].snapshot())


@app.post("/api/enforce")
def enforce():
    with lock:
        state["gw"].enforce = bool(request.json["enforce"])
        return jsonify(state["gw"].snapshot())


@app.post("/api/release")
def release():
    with lock:
        st = state["gw"].states[request.json["agent"]]
        st.status, st.risk, st.budget = "normal", 0, 0.0
        st.at_risk_from.clear()
        return jsonify(state["gw"].snapshot())


@app.post("/api/change")
def change():
    j = request.json
    with lock:
        state["gw"].register_change(j["agent"], j["reason"], add_read_zones=j.get("zones", []), valid_for_events=int(j.get("valid_for", 60)))
        return jsonify(state["gw"].snapshot())


@app.get("/api/eval")
def get_eval():
    if state["eval"] is None and not state["eval_running"]:
        threading.Thread(target=_compute_eval, daemon=True).start()
    return jsonify({"ready": state["eval"] is not None, "result": state["eval"]})


if __name__ == "__main__":
    threading.Thread(target=_compute_eval, daemon=True).start()   # warm the benchmark in the background
    app.run(host="127.0.0.1", port=5000, debug=False)
