# import os
# import requests
# import re
# from dotenv import load_dotenv

# # Presidio for PII Redaction
# from presidio_analyzer import AnalyzerEngine
# from presidio_anonymizer import AnonymizerEngine

# # LangChain Components
# from langchain_openai import ChatOpenAI
# from langchain_core.tools import tool
# from langchain.agents import AgentExecutor, create_tool_calling_agent
# from langchain_core.prompts import ChatPromptTemplate
# from langchain_community.tools import DuckDuckGoSearchResults

# #pip install langchain langchain-openai langchain-community duckduckgo-search presidio-analyzer presidio-anonymizer requests python-dotenv

# # Example Frontend implementation
# # from django.http import JsonResponse
# # from .chatbot_client import get_chatbot_response
# # from .models import VulnerabilityReport # Assuming you have a model

# # def chat_api_view(request):
# #     user_question = request.POST.get('question')
# #     report_id = request.POST.get('report_id')
    
# #     # Fetch your JSON report from PostgreSQL
# #     report = VulnerabilityReport.objects.get(id=report_id)
# #     raw_json_data = report.json_data 
    
# #     # Get the AI response
# #     answer = get_chatbot_response(user_question, raw_json_data)
    
# #     return JsonResponse({"answer": answer})

# def verify_link(url):
#     """Checks if a URL is alive and returns a 200 OK status."""
#     try:
#         # Use a short timeout and a standard User-Agent to avoid blocks
#         headers = {'User-Agent': 'Mozilla/5.0'}
#         response = requests.head(url, headers=headers, timeout=3, allow_redirects=True)
#         if response.status_code == 200:
#             return True
#         return False
#     except requests.RequestException:
#         return False

# # Load environment variables (e.g., OPENAI_API_KEY)
# load_dotenv()

# # ==========================================
# # 1. PII Redaction Setup
# # ==========================================
# analyzer = AnalyzerEngine()
# anonymizer = AnonymizerEngine()

# def scrub_report_data(report_text: str) -> str:
#     """
#     Analyzes the text for PII (IPs, emails, names, etc.) and replaces them 
#     with placeholder tags like [IP_ADDRESS] or [EMAIL_ADDRESS].
#     """
#     # Analyze text for PII
#     results = analyzer.analyze(text=report_text, language='en')
#     # Redact the findings
#     anonymized_result = anonymizer.anonymize(text=report_text, analyzer_results=results)
#     return anonymized_result.text

# # ==========================================
# # 2. LangChain Tools Setup
# # ==========================================
# def verify_link(url: str) -> bool:
#     """Checks if a URL is alive and returns a 200 OK status."""
#     try:
#         headers = {'User-Agent': 'Mozilla/5.0'}
#         response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
#         return response.status_code == 200
#     except requests.RequestException:
#         return False

# @tool
# def search_and_verify_resources(query: str) -> str:
#     """
#     Searches the internet for information on a vulnerability and verifies 
#     that the returned URLs are accessible. Use this when the user asks for 
#     more context, websites, or videos about a specific threat.
#     """
#     # Using DuckDuckGo for free tier testing; swap to Tavily or Google Search in production.
#     search = DuckDuckGoSearchResults(num_results=5)
#     raw_results = search.run(query)
    
#     # Simple regex to extract URLs from the raw search string
#     urls = re.findall(r'(https?://[^\s\]]+)', raw_results)
    
#     valid_urls = []
#     for url in set(urls): # Use set to remove duplicates
#         if verify_link(url):
#             valid_urls.append(url)
            
#     if not valid_urls:
#         return "I found some resources, but the links were dead or inaccessible. Please try a different query."
        
#     return f"Here are verified, accessible resources I found: {', '.join(valid_urls)}. \nRaw context: {raw_results}"

# # ==========================================
# # 3. Agent Architecture Setup
# # ==========================================
# def get_chatbot_response(user_question: str, raw_report_json: str) -> str:
#     """
#     Main function to be called from Django views.py.
#     Takes the user's question and the raw report, scrubs the report, 
#     and passes it to the LangChain agent.
#     """
#     # 1. Scrub the sensitive data first
#     safe_report_data = scrub_report_data(raw_report_json)
    
#     # 2. Initialize the LLM (using OpenAI GPT-4o-mini as a fast, capable default)
#     llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2)
    
#     # 3. Bind our custom tools to the LLM
#     tools = [search_and_verify_resources]
    
#     # 4. Create the System Prompt
#     prompt = ChatPromptTemplate.from_messages([
#         ("system", "You are a helpful cybersecurity assistant for an internal IT team. "
#                    "You are provided with an anonymized vulnerability report. "
#                    "Answer the user's questions based on the report. If they ask for external "
#                    "resources, tutorials, or fixes, use your search tool to find verified links.\n\n"
#                    "Context Report:\n{report_data}"),
#         ("human", "{input}"),
#         ("placeholder", "{agent_scratchpad}"),
#     ])
    
#     # 5. Construct and run the Agent
#     agent = create_tool_calling_agent(llm, tools, prompt)
#     agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
    
#     # Execute the agent
#     response = agent_executor.invoke({
#         "input": user_question,
#         "report_data": safe_report_data
#     })
    
#     return response["output"]