import os
import time
import base64
import json
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

PORT = int(os.environ.get("PORT", 10305))
OB = "OB55"

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

JWT_API_PRIMARY  = "https://ff-jwt-gen-api.lovable.app/api/public/token"
JWT_API_FALLBACK = "https://jwt-eat-zhogo.vercel.app/jwt"

SERVER_ME = "https://clientbp.ppmainecoonghj.com/"
VERSION_URL = "https://version.ffmax.purplevioleto.com/live/ver.php?lang=ar&device=android"

BASE_DIR = Path(__file__).resolve().parent
ACCOUNTS_FILE = BASE_DIR / "accs.txt"

REFRESH_SECONDS = max(60, int(os.environ.get("FRIEND_SPAM_REFRESH_SECONDS", "600")))


def decode_jwt(token: str):
    try:
        if not isinstance(token, str):
            return None, None, None
        token = token.strip()
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None
        p = parts[1]
        p += "=" * (-len(p) % 4)
        raw = base64.urlsafe_b64decode(p.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        account_id = data.get("account_id")
        if account_id is None:
            return None, None, None
        nickname = data.get("nickname") or data.get("name")
        region = (
            data.get("noti_region") or data.get("notiRegion")
            or data.get("lock_region") or data.get("lockRegion")
            or data.get("region")
        )
        return str(account_id), nickname, region
    except Exception as exc:
        print(f"[JWT] decode failed: {exc}")
        return None, None, None


def _extract_token(data):
    if isinstance(data, dict):
        for key in ("token", "jwt", "access_token"):
            v = data.get(key)
            if isinstance(v, str) and v.count(".") == 2:
                return v.strip()
        for v in data.values():
            found = _extract_token(v)
            if found:
                return found
    elif isinstance(data, list):
        for v in data:
            found = _extract_token(v)
            if found:
                return found
    return None


def generate_jwt_from_uid_password(uid: str, password: str):
    try:
        r = requests.get(
            JWT_API_PRIMARY,
            params={"uid": uid, "password": password},
            timeout=20, verify=False
        )
        r.raise_for_status()
        data = r.json()
        token = _extract_token(data)
        if token:
            account_id, jwt_nick, jwt_region = decode_jwt(token)
            if account_id:
                nickname = (data.get("nickname") or data.get("name") if isinstance(data, dict) else None) or jwt_nick
                region = (data.get("region") if isinstance(data, dict) else None) or jwt_region
                return token, account_id, nickname, region
    except Exception as exc:
        print(f"[JWT-1] failed: {exc}")

    try:
        r = requests.get(
            f"{JWT_API_FALLBACK}?eat={uid}:{password}",
            timeout=20, verify=False
        )
        r.raise_for_status()
        data = r.json()
        token = _extract_token(data)
        if token:
            account_id, jwt_nick, jwt_region = decode_jwt(token)
            if account_id:
                nickname = (data.get("nickname") or data.get("name") if isinstance(data, dict) else None) or jwt_nick
                region = (data.get("region") if isinstance(data, dict) else None) or jwt_region
                return token, account_id, nickname, region
    except Exception as exc:
        print(f"[JWT-2] failed: {exc}")

    return None, None, None, None


def load_accounts():
    accounts = []
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                uid, pw = line.split(":", 1)
                uid, pw = uid.strip(), pw.strip()
                if uid and pw:
                    accounts.append({"uid": uid, "pw": pw})
        print(f"[+] {len(accounts)} accounts loaded from {ACCOUNTS_FILE}")
    except FileNotFoundError:
        print(f"[!] {ACCOUNTS_FILE} not found")
    except Exception as exc:
        print(f"[!] load_accounts error: {exc}")
    return accounts


friend_spam_accounts = []
friend_spam_last_reload = 0
friend_spam_reload_lock = threading.Lock()
friend_spam_active = {}
friend_spam_lock = threading.Lock()


def _friend_spam_login(uid, password):
    try:
        t, acc_id, nick, region = generate_jwt_from_uid_password(uid, password)
        if t and acc_id:
            return {
                "jwt": t,
                "account_id": str(acc_id),
                "server_url": SERVER_ME,
                "uid": uid
            }
    except Exception:
        pass
    return None


def friend_spam_reload():
    global friend_spam_accounts, friend_spam_last_reload
    if not friend_spam_reload_lock.acquire(blocking=False):
        return
    try:
        accs = load_accounts()
        new_accs = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_friend_spam_login, a["uid"], a["pw"]): a
                for a in accs
            }
            for fut in as_completed(futures):
                try:
                    s = fut.result(timeout=15)
                    if s:
                        new_accs.append(s)
                except Exception:
                    pass
        if new_accs:
            friend_spam_accounts = new_accs
            print(f"[FRIEND-SPAM] reload: {len(new_accs)} accounts active")
        else:
            print(f"[FRIEND-SPAM] reload failed, kept {len(friend_spam_accounts)}")
        friend_spam_last_reload = time.time()
    finally:
        friend_spam_reload_lock.release()


def friend_spam_refresh_worker():
    while True:
        try:
            time.sleep(REFRESH_SECONDS)
            friend_spam_reload()
        except Exception as e:
            print(f"[FRIEND-SPAM] refresh error: {e}")


def _build_friend_packet(account_id, target_uid):
    fields = {1: int(account_id), 2: int(target_uid), 3: 22}
    pk = bytearray()
    for f, v in fields.items():
        n = (f << 3) | 0
        ev = []
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                b |= 0x80
            ev.append(b)
            if not n:
                break
        pk.extend(bytes(ev))

        ev2 = []
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                b |= 0x80
            ev2.append(b)
            if not v:
                break
        pk.extend(bytes(ev2))
    return bytes(pk)


def _friend_spam_send_one(session_data, target_uid):
    try:
        version = requests.get(VERSION_URL, timeout=8).json().get(
            "latest_release_version", "2.101.X"
        )
        payload = _build_friend_packet(session_data["account_id"], target_uid)
        encrypted = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(payload, 16))

        headers = {
            "Authorization": f"Bearer {session_data['jwt']}",
            "ReleaseVersion": version,
            "X-GA": "v1 1",
            "X-Unity-Version": "2022.3.47f1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        requests.post(
            f"{session_data['server_url']}RequestAddingFriend",
            headers=headers,
            data=encrypted,
            timeout=10,
            verify=False
        )
        return True
    except Exception:
        return False


def _friend_spam_batch(target_uid, accounts):
    use = accounts[:100]
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(_friend_spam_send_one, a, target_uid) for a in use]
        for f in as_completed(futures):
            try:
                f.result(timeout=15)
            except Exception:
                pass


def _friend_spam_worker(chat_id, target_uid, is_permanent):
    try:
        while True:
            with friend_spam_lock:
                if chat_id not in friend_spam_active:
                    break
                if target_uid not in friend_spam_active[chat_id]:
                    break

            if time.time() - friend_spam_last_reload > REFRESH_SECONDS * 2:
                threading.Thread(target=friend_spam_reload, daemon=True).start()

            if not is_permanent:
                with friend_spam_lock:
                    end_time = friend_spam_active.get(chat_id, {}).get(target_uid, {}).get("end")
                if end_time and time.time() > end_time:
                    with friend_spam_lock:
                        if chat_id in friend_spam_active and target_uid in friend_spam_active[chat_id]:
                            del friend_spam_active[chat_id][target_uid]
                    print(f"[FRIEND-SPAM] ended on {target_uid}")
                    break

            if friend_spam_accounts:
                try:
                    _friend_spam_batch(target_uid, friend_spam_accounts)
                except Exception as e:
                    print(f"[FRIEND-SPAM] batch error: {e}")

            time.sleep(1.5)
    except Exception as e:
        print(f"[FRIEND-SPAM] worker crashed: {e}")


app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    with friend_spam_lock:
        active_spam = sum(len(v) for v in friend_spam_active.values())
    return jsonify({
        "status": "online",
        "service": "Friend Spam API",
        "version": OB,
        "accounts_loaded": len(friend_spam_accounts),
        "active_spams": active_spam,
        "usage": "GET or POST /friend_spam?uid=PLAYER_UID&duration=SECONDS&chat_id=NAME",
    })



@app.route("/friend_spam", methods=["GET", "POST"])
def api_friend_spam_start():
    data = request.get_json(silent=True) or {}

    uid = data.get("uid") or request.args.get("uid")
    duration_raw = data.get("duration") or request.args.get("duration") or 900
    chat_id = data.get("chat_id") or request.args.get("chat_id") or "default"

    if not uid or not str(uid).isdigit():
        return jsonify({"success": False, "error": "Invalid UID"}), 400

    uid = str(uid)

    try:
        duration = int(duration_raw)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "duration must be integer seconds"}), 400

    if len(friend_spam_accounts) < 10:
        threading.Thread(target=friend_spam_reload, daemon=True).start()
        time.sleep(2)

    if not friend_spam_accounts:
        return jsonify({"success": False, "error": "No active accounts in accs.txt"}), 503

    with friend_spam_lock:
        if chat_id not in friend_spam_active:
            friend_spam_active[chat_id] = {}
        if uid in friend_spam_active[chat_id]:
            return jsonify({
                "success": False,
                "error": "Spam already running on this UID"
            }), 400

        end_time = time.time() + duration if duration > 0 else None
        friend_spam_active[chat_id][uid] = {"end": end_time}

    threading.Thread(
        target=_friend_spam_worker,
        args=(chat_id, uid, duration == 0),
        daemon=True,
        name=f"friend-spam-{uid}"
    ).start()

    return jsonify({
        "success": True,
        "message": f"Friend spam started on {uid}",
        "target": uid,
        "duration_seconds": duration,
        "is_permanent": duration == 0,
        "accounts_used": min(100, len(friend_spam_accounts)),
        "total_accounts": len(friend_spam_accounts)
    })


@app.route("/friend_spam/stop", methods=["GET", "POST"])
def api_friend_spam_stop():
    data = request.get_json(silent=True) or {}
    uid = data.get("uid") or request.args.get("uid")
    chat_id = data.get("chat_id") or request.args.get("chat_id") or "default"

    if not uid:
        return jsonify({"success": False, "error": "UID required"}), 400
    uid = str(uid)

    with friend_spam_lock:
        if chat_id in friend_spam_active and uid in friend_spam_active[chat_id]:
            del friend_spam_active[chat_id][uid]
            return jsonify({"success": True, "message": f"Spam stopped on {uid}"})

    return jsonify({"success": False, "error": "No spam on this UID"}), 404


@app.route("/friend_spam/stop_all", methods=["GET", "POST"])
def api_friend_spam_stop_all():
    with friend_spam_lock:
        total = 0
        for chat in list(friend_spam_active.keys()):
            total += len(friend_spam_active[chat])
            friend_spam_active[chat].clear()
    return jsonify({"success": True, "stopped": total})


@app.route("/friend_spam/show", methods=["GET"])
def api_friend_spam_show():
    chat_id = request.args.get("chat_id") or "default"
    with friend_spam_lock:
        spams = dict(friend_spam_active.get(chat_id, {}))

    if not spams:
        return jsonify({"success": True, "count": 0, "active": []})

    now = time.time()
    result = []
    for uid, data in spams.items():
        if data["end"] is None:
            remaining = None
            status = "permanent"
        else:
            remaining = max(0, int(data["end"] - now))
            status = f"{remaining}s"
        result.append({
            "uid": uid,
            "status": status,
            "remaining_seconds": remaining,
            "is_permanent": data["end"] is None
        })

    return jsonify({"success": True, "count": len(result), "active": result})


@app.route("/friend_spam/reload", methods=["GET", "POST"])
def api_friend_spam_reload():
    threading.Thread(target=friend_spam_reload, daemon=True).start()
    return jsonify({"success": True, "message": "Reloading accounts in background"})


@app.route("/friend_spam/status", methods=["GET"])
def api_friend_spam_status():
    with friend_spam_lock:
        total_active = sum(len(v) for v in friend_spam_active.values())

    return jsonify({
        "success": True,
        "accounts_loaded": len(friend_spam_accounts),
        "active_spams": total_active,
        "last_reload": friend_spam_last_reload,
        "seconds_since_reload": int(time.time() - friend_spam_last_reload) if friend_spam_last_reload else 0,
        "auto_refresh_interval": REFRESH_SECONDS
    })


threading.Thread(target=friend_spam_reload, daemon=True, name="friend-spam-initial").start()
threading.Thread(target=friend_spam_refresh_worker, daemon=True, name="friend-spam-refresh").start()


if __name__ == "__main__":
    print("=" * 60)
    print("  Friend Spam API (GET + POST)")
    print("=" * 60)
    print(f"  Accounts file: {ACCOUNTS_FILE}")
    print(f"  Port: {PORT}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)