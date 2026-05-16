from chatbot.chat_service import generate_chat_reply

USER_ID = 5  


while True:
    question = input("\nYou: ").strip()

    if question.lower() in {"exit", "quit"}:
        break

    try:
        reply = generate_chat_reply(USER_ID, question)
        print("\nBot:", reply)
    except Exception as e:
        print("\nERROR:", e)