import os
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
    return resp.output_text[:3500]
