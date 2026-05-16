from chatbot.kb_service import search_knowledge

results = search_knowledge("CWE-89")
print(results[:1])

results2 = search_knowledge("Broken Access Control")
print(results2[:1])