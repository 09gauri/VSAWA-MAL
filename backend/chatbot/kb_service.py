from pathlib import Path
import json

KB_DIR = Path(__file__).resolve().parent / "knowledge_base"

def normalize(text: str) -> str:
    return (text or "").lower().replace(" ", "").replace("-", "").replace("_", "")

def load_knowledge():
    knowledge = []
    for file in KB_DIR.glob("*.json"):
        with open(file, "r", encoding="utf-8") as f:
            knowledge.append(json.load(f))
    return knowledge

KNOWLEDGE = load_knowledge()

def search_knowledge(query: str):
    q = normalize(query)
    results = []
    idx = 1

    for kb in KNOWLEDGE:
        owasp_name = normalize(kb.get("category", ""))

        # Match whole OWASP category
        if q in owasp_name:
            for cwe in kb.get("cwes", []):
                results.append({
                    "id": f"VULN-{str(idx).zfill(3)}",
                    "name": cwe.get("name"),
                    "cwe": cwe.get("cwe_id"),
                    "owasp": f'{kb.get("owasp_id")} - {kb.get("category")}',
                    "impact": cwe.get("impact"),
                    "prevention": cwe.get("prevention"),
                    "fixation": cwe.get("fixation"),
                    "mitigation": cwe.get("mitigation")
                })
                idx += 1
            return results

        # Match individual CWE
        for cwe in kb.get("cwes", []):
            if q in normalize(cwe.get("name", "")) or q in normalize(cwe.get("cwe_id", "")):
                results.append({
                    "id": f"VULN-{str(idx).zfill(3)}",
                    "name": cwe.get("name"),
                    "cwe": cwe.get("cwe_id"),
                    "owasp": f'{kb.get("owasp_id")} - {kb.get("category")}',
                    "impact": cwe.get("impact"),
                    "prevention": cwe.get("prevention"),
                    "fixation": cwe.get("fixation"),
                    "mitigation": cwe.get("mitigation")
                })
                return results

    return results

def estimate_severity(impact: str) -> str:
    text = (impact or "").lower()
    if "takeover" in text or "compromise" in text:
        return "HIGH"
    if "unauthorized" in text or "leak" in text:
        return "MEDIUM"
    return "LOW"