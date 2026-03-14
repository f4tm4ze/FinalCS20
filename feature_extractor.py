
import numpy as np
import threading
import os
import zipfile
import tempfile
import shutil
from dataclasses import dataclass, field

try:
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK

try:
    from androguard.misc import AnalyzeAPK
    HAS_ANALYZE = True
except ImportError:
    HAS_ANALYZE = False

from fuzzywuzzy import fuzz


# ── Rule-based heuristic engine ───────────────────────────────────────────────
# Derived from research showing these are the most indicative features across
# Drebin, CICAndMal2017, AM, and AMSF datasets.
#
# Each rule is (rule_id, label, severity, match_strings)
# severity: "critical" | "high" | "medium"
# A feature triggers the rule if ANY match_string is a substring of it (case-insensitive).

HEURISTIC_RULES = [
    # ── SMS abuse (Joker, premium-rate fraud) ─────────────────────────────────
    ("R01", "SMS sending capability",          "critical", ["SEND_SMS", "sendTextMessage", "SmsManager"]),
    ("R02", "SMS reading / interception",      "high",     ["RECEIVE_SMS", "READ_SMS", "abortBroadcast"]),

    # ── Telephony abuse ───────────────────────────────────────────────────────
    ("R03", "Phone call capability",           "high",     ["CALL_PHONE", "PROCESS_OUTGOING_CALLS", "TelephonyManager"]),

    # ── Location tracking ─────────────────────────────────────────────────────
    ("R04", "Precise location access",         "high",     ["ACCESS_FINE_LOCATION", "getLastKnownLocation", "requestLocationUpdates"]),

    # ── Dangerous permissions (from Drebin/AM datasets) ───────────────────────
    ("R05", "App uninstall capability",        "high",     ["UNINSTALL_SHORTCUT", "DELETE_PACKAGES", "REQUEST_UNINSTALL_PACKAGES"]),
    ("R06", "Vibrate / notification abuse",    "medium",   ["VIBRATE"]),
    ("R07", "Device admin / root access",      "critical", ["BIND_DEVICE_ADMIN", "ROOT", "su\x00", "/system/bin/su"]),

    # ── Reflection / dynamic loading (obfuscation indicators) ────────────────
    ("R08", "Java reflection usage",           "high",     ["getCanonicalName", "getDeclaredMethod", "forName", "invoke"]),
    ("R09", "Dynamic code loading",            "critical", ["DexClassLoader", "PathClassLoader", "loadDex", "dalvik.system"]),

    # ── Network / C2 indicators ───────────────────────────────────────────────
    ("R10", "Raw socket / network access",     "medium",   ["INTERNET", "java.net.Socket", "HttpURLConnection", "OkHttp"]),
    ("R11", "Network state monitoring",        "medium",   ["ACCESS_NETWORK_STATE", "CHANGE_NETWORK_STATE", "ConnectivityManager"]),

    # ── Surveillance ──────────────────────────────────────────────────────────
    ("R12", "Camera access",                   "medium",   ["CAMERA", "android.hardware.camera"]),
    ("R13", "Microphone / audio recording",    "high",     ["RECORD_AUDIO", "AudioRecord", "MediaRecorder"]),
    ("R14", "Contact / account harvesting",    "high",     ["READ_CONTACTS", "GET_ACCOUNTS", "AccountManager"]),

    # ── Persistence ───────────────────────────────────────────────────────────
    ("R15", "Boot persistence",                "high",     ["RECEIVE_BOOT_COMPLETED", "BOOT_COMPLETED"]),
    ("R16", "Foreground service abuse",        "medium",   ["FOREGROUND_SERVICE", "startForeground"]),

    # ── Known malware class patterns ─────────────────────────────────────────
    ("R17", "Known Joker/adware class pattern","critical", ["com.joker", "joker.sdk", "com.simple.support"]),
    ("R18", "Native code execution",           "high",     ["System.loadLibrary", "Runtime.exec", "ProcessBuilder"]),
]

# Minimum severity to trigger a heuristic flag
# critical = always flag | high = flag if 2+ hits | medium = informational only
CRITICAL_SEVERITY = {"critical"}
HIGH_SEVERITY     = {"critical", "high"}


@dataclass
class HeuristicResult:
    flagged: bool = False
    triggered_rules: list = field(default_factory=list)   # list of (rule_id, label, severity, matched_on)
    critical_hits: int = 0
    high_hits: int = 0
    medium_hits: int = 0

    @property
    def severity_summary(self) -> str:
        if self.critical_hits > 0:
            return "CRITICAL"
        if self.high_hits >= 2:
            return "HIGH"
        if self.high_hits == 1:
            return "MEDIUM"
        return "LOW"


def run_heuristics(app_features_set: set) -> HeuristicResult:
    """
    Run all heuristic rules against the extracted feature set.
    Returns a HeuristicResult with triggered rules and a flagged verdict.
    """
    result = HeuristicResult()
    features_lower = {f.lower() for f in app_features_set}

    for rule_id, label, severity, patterns in HEURISTIC_RULES:
        matched_on = None
        for pattern in patterns:
            pat_lower = pattern.lower()
            hit = next((f for f in features_lower if pat_lower in f), None)
            if hit:
                matched_on = hit
                break

        if matched_on:
            result.triggered_rules.append((rule_id, label, severity, matched_on))
            if severity == "critical":
                result.critical_hits += 1
            elif severity == "high":
                result.high_hits += 1
            else:
                result.medium_hits += 1

    # Flag if any critical hit OR 2+ high hits
    result.flagged = result.critical_hits > 0 or result.high_hits >= 2
    return result


def _extract_apk_from_xapk(xapk_path):
    """
    Extract the primary .apk from an .xapk (which is a ZIP).
    Returns a path to a temp .apk file, or None if not found.
    The caller is responsible for deleting the temp file.
    """
    try:
        with zipfile.ZipFile(xapk_path, 'r') as z:
            apk_entries = [
                name for name in z.namelist()
                if name.endswith('.apk') and '/' not in name  # top-level APKs only
            ]
            if not apk_entries:
                # Fallback: any .apk inside
                apk_entries = [name for name in z.namelist() if name.endswith('.apk')]

            if not apk_entries:
                print("[feature_extractor] No .apk found inside XAPK")
                return None

            # Pick the largest APK (usually the base/main one)
            apk_entries.sort(key=lambda n: z.getinfo(n).file_size, reverse=True)
            chosen = apk_entries[0]
            print(f"[feature_extractor] Extracting '{chosen}' from XAPK")

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.apk')
            tmp.write(z.read(chosen))
            tmp.close()
            return tmp.name
    except Exception as e:
        print(f"[feature_extractor] XAPK extraction error: {e}")
        return None


def _analyze_apk_with_timeout(apk_path, timeout=60):
    """
    Run AnalyzeAPK in a thread with a timeout.
    Returns (a, d, dx) or (None, None, None) if it times out.
    """
    result = [None, None, None]
    error  = [None]

    def target():
        try:
            from androguard.misc import AnalyzeAPK
            result[0], result[1], result[2] = AnalyzeAPK(apk_path)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        print(f"[feature_extractor] AnalyzeAPK timed out after {timeout}s — falling back to APK-only mode")
        return None, None, None

    if error[0]:
        print(f"[feature_extractor] AnalyzeAPK error: {error[0]} — falling back to APK-only mode")
        return None, None, None

    return result[0], result[1], result[2]


def extract_features(apk_path, most_relevant_features):
    """
    Extract features from an APK or XAPK file and map them against the most
    relevant feature list used during model training.

    Supports:
      - .apk  files directly
      - .xapk files (extracts the primary APK first)

    Strategy:
      1. If XAPK, unpack the primary APK to a temp file.
      2. Try AnalyzeAPK with a timeout to get DEX classes/methods.
      3. If it times out or fails, fall back to APK-only parsing.
      4. Match using: exact → substring → fuzzy fallback.
    """
    temp_apk_path = None  # track temp file from XAPK extraction

    try:
        classes = []
        methods = []

        # ── Step 0: Handle XAPK ───────────────────────────────────────────────
        ext = os.path.splitext(apk_path)[1].lower()
        actual_apk_path = apk_path

        if ext == '.xapk':
            print(f"[feature_extractor] XAPK detected — extracting inner APK...")
            temp_apk_path = _extract_apk_from_xapk(apk_path)
            if temp_apk_path is None:
                raise ValueError("Could not extract a valid APK from the XAPK file.")
            actual_apk_path = temp_apk_path
        # ─────────────────────────────────────────────────────────────────────

        # ── Step 1: Try full DEX analysis (with timeout) ──────────────────────
        file_size_mb = os.path.getsize(actual_apk_path) / (1024 * 1024)
        if file_size_mb > 100:
            print(f"[feature_extractor] File is {file_size_mb:.1f} MB — skipping DEX analysis, using APK-only mode")
            a, d, dx = None, None, None
        else:
            a, d, dx = _analyze_apk_with_timeout(actual_apk_path, timeout=30)

        if a is None:
            a = APK(actual_apk_path)
        else:
            dex_list = d if isinstance(d, list) else [d]
            for dex in dex_list:
                if dex is None:
                    continue
                try:
                    for dex_class in dex.get_classes():
                        name = dex_class.get_name()
                        if name:
                            classes.append(name)
                        for method in dex_class.get_methods():
                            mname = method.get_name()
                            if mname:
                                methods.append(mname)
                except Exception as e:
                    print(f"[feature_extractor] DEX parse warning: {e}")

        print(f"[feature_extractor] DEX classes: {len(classes)}, methods: {len(methods)}")
        # ─────────────────────────────────────────────────────────────────────

        # ── Step 2: APK-level features ────────────────────────────────────────
        permissions       = a.get_permissions()  or []
        hardware_software = a.get_features()     or []
        activities        = a.get_activities()   or []
        services          = a.get_services()     or []
        receivers         = a.get_receivers()    or []
        providers         = a.get_providers()    or []

        all_intents = []
        for component_type, components in [
            ("activity", activities),
            ("service",  services),
            ("receiver", receivers),
            ("provider", providers),
        ]:
            for comp in components:
                intent = a.get_intent_filters(component_type, comp)
                if intent:
                    for key in ("action", "category"):
                        val = intent.get(key)
                        if val is not None:
                            if isinstance(val, list):
                                all_intents.extend(v for v in val if v)
                            else:
                                all_intents.append(val)

        app_extracted_features = (
            permissions
            + hardware_software
            + activities
            + providers
            + receivers
            + services
            + all_intents
            + classes
            + methods
        )
        # ─────────────────────────────────────────────────────────────────────

        print(f"[feature_extractor] Total extracted features: {len(app_extracted_features)}")

        # ── Step 3: Match against trained feature list ────────────────────────
        app_features_set = {str(f) for f in app_extracted_features if f is not None}

        extraction_result = []
        matches = []

        for required_feature in most_relevant_features:
            req_str = str(required_feature) if required_feature is not None else ""

            if req_str in app_features_set:
                extraction_result.append(1)
                matches.append((required_feature, req_str))
                continue

            sub_match = next(
                (f for f in app_features_set if req_str and req_str in f),
                None
            )
            if sub_match:
                extraction_result.append(1)
                matches.append((required_feature, sub_match))
                continue

            best_score = 0
            best_feat  = None
            for app_feat in app_features_set:
                score = fuzz.ratio(req_str, app_feat)
                if score > best_score:
                    best_score = score
                    best_feat  = app_feat
                if best_score >= 95:
                    break

            if best_score >= 90:
                extraction_result.append(1)
                matches.append((required_feature, best_feat))
            else:
                extraction_result.append(0)
        # ─────────────────────────────────────────────────────────────────────

        print(f"\n--- Matches found: {len(matches)} / {len(most_relevant_features)} features ---")
        for match in matches[:10]:
            print(f"  {match[0]}  →  {match[1]}")
        if len(matches) > 10:
            print(f"  ... and {len(matches) - 10} more")

        # ── Step 4: Run heuristic rules ───────────────────────────────────────
        heuristic = run_heuristics(app_features_set)
        print(f"\n--- Heuristics: flagged={heuristic.flagged} | "
              f"critical={heuristic.critical_hits} high={heuristic.high_hits} medium={heuristic.medium_hits} ---")
        for r in heuristic.triggered_rules:
            print(f"  [{r[2].upper()}] {r[0]} {r[1]}  →  '{r[3]}'")
        # ─────────────────────────────────────────────────────────────────────

        return np.array(extraction_result).reshape(1, -1), matches, heuristic

    except Exception as e:
        print(f"Error in feature extraction: {e}")
        import traceback
        traceback.print_exc()
        return np.zeros((1, len(most_relevant_features))), [], HeuristicResult()

    finally:
        # Clean up temp APK extracted from XAPK
        if temp_apk_path and os.path.exists(temp_apk_path):
            try:
                os.unlink(temp_apk_path)
            except Exception:
                pass
