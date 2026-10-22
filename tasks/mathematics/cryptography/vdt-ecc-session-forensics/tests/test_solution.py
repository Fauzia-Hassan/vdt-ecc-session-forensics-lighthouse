import hashlib
import json
import os
import numpy as np
import pandas as pd
import pytest
from scipy.stats import theilslopes

DATA_DIR = "/app/data"
RESULT_PATH = "/app/results/session_audit.json"


def mod_inv(a, m):
    return pow(a % m, m - 2, m)


def ec_add(P, R, c_coeff, q):
    if P is None:
        return R
    if R is None:
        return P
    u1, v1 = P
    u2, v2 = R
    if u1 == u2 and (v1 + v2) % q == 0:
        return None
    if P != R:
        lam = ((v2 - v1) * mod_inv(u2 - u1, q)) % q
    else:
        if v1 == 0:
            return None
        lam = ((3 * u1 * u1 + c_coeff) * mod_inv(2 * v1, q)) % q
    u3 = (lam * lam - u1 - u2) % q
    v3 = (lam * (u1 - u3) - v1) % q
    return (u3, v3)


def ec_mul(k, P, c_coeff, q):
    res = None
    addend = P
    k = int(k)
    while k > 0:
        if k & 1:
            res = ec_add(res, addend, c_coeff, q)
        addend = ec_add(addend, addend, c_coeff, q)
        k >>= 1
    return res


def compute_exact_order(g_pt, c_coeff, q):
    m = int(np.ceil(np.sqrt(4 * np.sqrt(q)))) + 2
    baby = {}
    cur = None
    for j in range(m):
        baby[cur] = j
        cur = ec_add(cur, g_pt, c_coeff, q)
    step = ec_mul(m, g_pt, c_coeff, q)
    center = ec_mul(q + 1, g_pt, c_coeff, q)
    k_range = int(np.ceil(2 * np.sqrt(q) / m)) + 2
    cands = []
    for i in range(-k_range, k_range + 1):
        if i >= 0:
            giant = ec_add(center, ec_mul(i, step, c_coeff, q), c_coeff, q)
        else:
            neg_step = (step[0], (-step[1]) % q)
            giant = ec_add(center, ec_mul(-i, neg_step, c_coeff, q), c_coeff, q)
        if giant in baby:
            cand = q + 1 + i * m - baby[giant]
            if cand > 0 and ec_mul(cand, g_pt, c_coeff, q) is None:
                cands.append(cand)
    n_val = min(cands)
    temp = n_val
    d = 2
    factors = set()
    while d * d <= temp:
        while temp % d == 0:
            factors.add(d)
            temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    for f in factors:
        while n_val % f == 0 and ec_mul(n_val // f, g_pt, c_coeff, q) is None:
            n_val //= f
    return n_val


def h_func(*args):
    joined = "|".join(str(a) for a in args)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def decrypt_payload(key_str, hex_cipher):
    data_bytes = bytes.fromhex(hex_cipher)
    out = bytearray(len(data_bytes))
    block_idx = 0
    pos = 0
    while pos < len(data_bytes):
        ks = hashlib.sha256(f"{key_str}|{block_idx}".encode("utf-8")).digest()
        take = min(len(ks), len(data_bytes) - pos)
        for i in range(take):
            out[pos + i] = data_bytes[pos + i] ^ ks[i]
        pos += take
        block_idx += 1
    return json.loads(bytes(out).decode("utf-8"))


@pytest.fixture(scope="module")
def ground_truth():
    with open(os.path.join(DATA_DIR, "system_params.json")) as f:
        sys_params = json.load(f)
    with open(os.path.join(DATA_DIR, "smartcard_dump.json")) as f:
        sc_dump = json.load(f)
    probes_df = pd.read_parquet(os.path.join(DATA_DIR, "biometric_probes.parquet"))
    with open(os.path.join(DATA_DIR, "packet_capture.jsonl")) as f:
        packets = [json.loads(line) for line in f if line.strip()]

    q = sys_params["curve"]["q"]
    c_coeff = sys_params["curve"]["c"]
    g_pt = tuple(sys_params["curve"]["g"])
    delta_t = sys_params["protocol_constants"]["delta_t_ms"]
    fuzzy_delta = sys_params["protocol_constants"]["fuzzy_delta"]
    sim_thresh = sys_params["protocol_constants"]["biometric_similarity_threshold"]

    order_n = compute_exact_order(g_pt, c_coeff, q)

    clock_models = {}
    for node_id, samples in sys_params["clock_calibration"].items():
        t_cs = np.array([s["t_cs_ms"] for s in samples])
        t_node = np.array([s["t_node_ms"] for s in samples])
        slope, intercept, _, _ = theilslopes(t_node, t_cs)
        clock_models[node_id] = (slope, intercept)

    def to_cs_time(node_id, t_raw):
        slope, intercept = clock_models[node_id]
        return (float(t_raw) - intercept) / slope

    sc_map = {sc["ID_V"]: sc for sc in sc_dump["smartcards"]}
    twin_map = {tw["ID_T"]: tw for tw in sc_dump["twins"]}
    probe_map = {row["session_id"]: row for _, row in probes_df.iterrows()}

    expected_sessions = []
    for pkt in sorted(packets, key=lambda x: x["session_id"]):
        sid = pkt["session_id"]
        vid = pkt["ID_V"]
        tid = pkt["ID_T"]
        sc = sc_map[vid]
        tw = twin_map[tid]
        p_row = probe_map[sid]

        b_prime = np.array([p_row[f"feat_{k:03d}"] for k in range(256)])
        tau_v = np.array(sc["tau_V"])
        sigma_prime_bits = np.floor((b_prime - tau_v) / fuzzy_delta + 0.5).astype(int) % 2

        sigma_enrolled_int = int(sc["beta_1"], 16) ^ int(sc["beta_2"], 16)
        sigma_enrolled_bits = np.array([int(b) for b in f"{sigma_enrolled_int:0256b}"])
        similarity = np.mean(sigma_prime_bits == sigma_enrolled_bits)

        if similarity < sim_thresh:
            expected_sessions.append({
                "session_id": sid,
                "status": "BIOMETRIC_FAIL",
                "failed_stage": "SC_LOGIN",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        beta_2_prime = f"{int(sc['beta_1'], 16) ^ sigma_enrolled_int:064x}"
        beta_3_prime = h_func(vid, sc["pw_V"], beta_2_prime, sc["r_V"])
        if beta_3_prime != sc["beta_3"]:
            expected_sessions.append({
                "session_id": sid,
                "status": "BIOMETRIC_FAIL",
                "failed_stage": "SC_LOGIN",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        t1_str = pkt["M1"]["T_1"]
        t2_str = pkt["M2"]["T_2"]
        d12 = float(t2_str) - to_cs_time(vid, t1_str)
        if not (0.0 <= d12 <= delta_t):
            expected_sessions.append({
                "session_id": sid,
                "status": "REPLAY_OR_DELAY",
                "failed_stage": "M1_CS",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        key_e1 = h_func(vid, t1_str, sc["beta_1"])
        m1_dec = decrypt_payload(key_e1, pkt["M1"]["E_1"])
        w1_expected = h_func(vid, sc["beta_1"], m1_dec["xi"])
        if m1_dec["W_1"] != w1_expected:
            expected_sessions.append({
                "session_id": sid,
                "status": "INTEGRITY_FAIL",
                "failed_stage": "M1_CS",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        t3_str = pkt["M2"]["T_3"]
        t4_str = pkt["M3"]["T_4"]
        d34 = to_cs_time(tid, t4_str) - float(t3_str)
        if not (0.0 <= d34 <= delta_t):
            expected_sessions.append({
                "session_id": sid,
                "status": "REPLAY_OR_DELAY",
                "failed_stage": "M2_T",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        w3_key = h_func(vid, tw["Z"], t3_str)
        m2_dec = decrypt_payload(w3_key, pkt["M2"]["E_2"])
        w2_expected = h_func(vid, m2_dec["W_1"], t3_str)
        if m2_dec["W_2"] != w2_expected:
            expected_sessions.append({
                "session_id": sid,
                "status": "INTEGRITY_FAIL",
                "failed_stage": "M2_T",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        t5_str = pkt["M3"]["T_5"]
        t6_str = pkt["M4"]["T_6"]
        d56 = float(t6_str) - to_cs_time(tid, t5_str)
        if not (0.0 <= d56 <= delta_t):
            expected_sessions.append({
                "session_id": sid,
                "status": "REPLAY_OR_DELAY",
                "failed_stage": "M3_CS",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        t7_str = pkt["M4"]["T_7"]
        t8_str = pkt["M4"]["T_8"]
        d78 = to_cs_time(vid, t8_str) - float(t7_str)
        if not (0.0 <= d78 <= delta_t):
            expected_sessions.append({
                "session_id": sid,
                "status": "REPLAY_OR_DELAY",
                "failed_stage": "M4_V",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        w5_key = h_func(m1_dec["W_1"], m1_dec["xi"], t5_str)
        m4_dec = decrypt_payload(w5_key, pkt["M4"]["E_3"])
        w4_expected = h_func(
            tid, vid, m4_dec["c"], m4_dec["r"], m4_dec["Z"], m4_dec["eta"]
        )
        if m4_dec["W_4"] != w4_expected:
            expected_sessions.append({
                "session_id": sid,
                "status": "INTEGRITY_FAIL",
                "failed_stage": "M4_V",
                "shared_point_u": None,
                "shared_point_v": None,
                "session_key_sk": None,
            })
            continue

        scalar = (int(m1_dec["xi"]) * int(m4_dec["eta"])) % order_n
        shared_pt = ec_mul(scalar, g_pt, c_coeff, q)
        pt_str = f"{shared_pt[0]},{shared_pt[1]}"
        sk = h_func(tid, vid, tw["Z"], sc["c"], pt_str, t5_str, m4_dec["W_4"])

        expected_sessions.append({
            "session_id": sid,
            "status": "VALID",
            "failed_stage": "NONE",
            "shared_point_u": shared_pt[0],
            "shared_point_v": shared_pt[1],
            "session_key_sk": sk,
        })

    return {"curve_order_n": order_n, "sessions": expected_sessions}


def test_output_exists_and_valid_schema():
    assert os.path.exists(RESULT_PATH), f"Missing output file at {RESULT_PATH}"
    with open(RESULT_PATH) as f:
        data = json.load(f)
    assert "curve_order_n" in data and isinstance(data["curve_order_n"], int)
    assert "sessions" in data and isinstance(data["sessions"], list)
    assert len(data["sessions"]) == 40


def test_curve_order(ground_truth):
    with open(RESULT_PATH) as f:
        data = json.load(f)
    assert data["curve_order_n"] == ground_truth["curve_order_n"]


def test_all_sessions_classification_and_keys(ground_truth):
    with open(RESULT_PATH) as f:
        data = json.load(f)

    sub_sessions = {s["session_id"]: s for s in data["sessions"]}
    for exp in ground_truth["sessions"]:
        sid = exp["session_id"]
        assert sid in sub_sessions, f"Missing session {sid}"
        got = sub_sessions[sid]
        assert got["status"] == exp["status"], (
            f"Session {sid}: expected status {exp['status']}, got {got['status']}"
        )
        assert got["failed_stage"] == exp["failed_stage"], (
            f"Session {sid}: expected stage {exp['failed_stage']}, got {got['failed_stage']}"
        )
        assert got["shared_point_u"] == exp["shared_point_u"], (
            f"Session {sid}: mismatch on shared_point_u"
        )
        assert got["shared_point_v"] == exp["shared_point_v"], (
            f"Session {sid}: mismatch on shared_point_v"
        )
        assert got["session_key_sk"] == exp["session_key_sk"], (
            f"Session {sid}: mismatch on session_key_sk"
        )
