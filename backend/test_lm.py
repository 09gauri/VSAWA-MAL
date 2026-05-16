from chatbot.lm_client import chat_with_lmstudio

messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "What is SQL injection? Answer in 2 lines."}
]

reply = chat_with_lmstudio(messages)
print("\n=== LM STUDIO REPLY ===\n")
print(reply)