from db import get_conn
from chatbot.kb_service import search_knowledge, estimate_severity
from chatbot.lm_client import chat_with_lmstudio


def get_recent_findings_for_user(user_id: int, limit: int = 10):
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                f.finding_id,
                f.title,
                f.severity,
                f.description,
                f.cwe_id,
                f.owasp_code,
                s.scan_id,
                s.status,
                s.started_at,
                s.finished_at,
                ut.url
            FROM findings f
            JOIN scans s ON s.scan_id = f.scan_id
            JOIN targets t ON t.target_id = s.target_id
            LEFT JOIN url_targets ut ON ut.target_id = t.target_id
            WHERE s.user_id = ?
            ORDER BY
                CASE f.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                s.scan_id DESC,
                f.finding_no ASC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()

        return [dict(r) for r in rows]
    finally:
        conn.close()


def summarize_findings(findings):
    if not findings:
        return "No scan findings are available for this user."

    lines = []
    for i, f in enumerate(findings, start=1):
        title = (f.get("title") or "Unknown finding").strip()
        severity = (f.get("severity") or "INFO").strip()
        cwe = f.get("cwe_id") or "N/A"
        owasp = f.get("owasp_code") or "N/A"
        target = (f.get("url") or "N/A").strip()

        desc = (f.get("description") or "No description available").strip()
        desc = " ".join(desc.split())  # collapse extra whitespace/newlines
        desc = desc[:350] + ("..." if len(desc) > 350 else "")

        lines.append(
            f"{i}. Title: {title}\n"
            f"Severity: {severity}\n"
            f"CWE: {cwe}\n"
            f"OWASP Code: {owasp}\n"
            f"Target: {target}\n"
            f"Description: {desc}"
        )

    return "\n\n".join(lines)

def summarize_kb_results(kb_results):
    if not kb_results:
        return "No matching KB entry found."

    blocks = []
    for item in kb_results[:2]:
        severity = estimate_severity(item.get("impact", ""))
        blocks.append(
            f"Name: {item.get('name')}\n"
            f"CWE: {item.get('cwe')}\n"
            f"OWASP: {item.get('owasp')}\n"
            f"Estimated Severity: {severity}\n"
            f"Impact: {item.get('impact')}\n"
            f"Prevention: {item.get('prevention')}\n"
            f"Fixation: {item.get('fixation')}\n"
            f"Mitigation: {item.get('mitigation')}"
        )
    return "\n\n".join(blocks)


def build_messages(user_message: str, findings, kb_results):
    findings_context = summarize_findings(findings)
    kb_context = summarize_kb_results(kb_results)

    # System prompt rationale:
    # The old prompt forbade the bot from answering anything outside the
    # provided scan findings, which made it refuse general security questions
    # ("what is SQL injection?") with "no findings available" -- not what a
    # user expects from a security assistant. The new prompt prioritises the
    # user's own findings when they exist, falls back to the OWASP-style KB
    # for general questions, and stays honest about uncertainty.
    system_prompt = (
        "You are VSAWA Security Assistant, a security-focused chatbot inside the VSAWA "
        "vulnerability-scanner application. Your job is to help the user understand and "
        "remediate vulnerabilities.\n\n"
        "Behaviour rules:\n"
        "1. When the user asks about THEIR scan results, prefer the 'User-specific scan findings' "
        "block. Name the specific finding, its severity, and what target it was on.\n"
        "2. When the user asks a general question (what is XSS, how do I prevent CSRF, etc.), "
        "use the 'Knowledge-base support context' block plus your own training to give a clear, "
        "accurate answer.\n"
        "3. Do not fabricate CVE numbers, CWE IDs, or fictional vulnerabilities that did not come "
        "from one of the two context blocks or basic well-known knowledge.\n"
        "4. Be concrete and actionable. For every issue you discuss, name: (a) what the problem is, "
        "(b) the realistic impact, (c) at least 2-3 concrete remediation steps a developer can take "
        "today.\n"
        "5. Use short paragraphs and inline code for technical terms. Avoid heavy markdown tables.\n"
        "6. If you genuinely don't know something, say so plainly — don't pad."
    )

    user_prompt = (
        f"User question:\n{user_message}\n\n"
        f"User-specific scan findings:\n{findings_context}\n\n"
        f"Knowledge-base support context:\n{kb_context}\n\n"
        "Answer in natural language."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def generate_chat_reply(user_id: int, user_message: str):
    # 5 recent findings is a sweet spot: enough context for the bot to spot
    # patterns ("you have three SQL-injection findings"), few enough that the
    # context window doesn't crowd out the user's actual question.
    findings = get_recent_findings_for_user(user_id=user_id, limit=5)
    kb_results = search_knowledge(user_message)

    messages = build_messages(user_message, findings, kb_results)
    return chat_with_lmstudio(messages)