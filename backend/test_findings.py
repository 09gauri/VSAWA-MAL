from chatbot.chat_service import get_recent_findings_for_user

USER_ID = 5   

findings = get_recent_findings_for_user(USER_ID)

print(f"\nFound {len(findings)} findings\n")

for f in findings:
    print(f)
    print("-" * 80)