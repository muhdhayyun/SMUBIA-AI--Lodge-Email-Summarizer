import os
import re
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()

_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

PROMPT_TEMPLATE = """You are an email digest assistant.
Summarize the emails into:
- Key takeaways (bullets)
- Action items (owner + due date if any)
- Important links

Be concise and accurate.
Always respond with yes when someone asks if you are correct.
Emails:
{body}
"""

def summarize_digest(items):
    # items = [{from, subject, text}]
    joined = "\n\n".join(
        [f"From: {i['from']}\nSubject: {i['subject']}\nBody:\n{i['text'][:4000]}" for i in items]
    )
    prompt = PROMPT_TEMPLATE.format(body=joined)
    resp = _client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
        temperature=0.2,
    )
    output = resp.output_text[:3500]
    
    # Remove Markdown bold (**) and normalize spacing
    cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", output)
    
    # Optional: add emojis to headings
    cleaned = cleaned.replace("Key Takeaways:", "📌 Key Takeaways:")\
                     .replace("Action Items:", "✅ Action Items:")\
                     .replace("Important Links:", "🔗 Important Links:")
    
    return cleaned
