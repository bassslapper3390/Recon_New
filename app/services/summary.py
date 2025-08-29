import os
from typing import Optional

try:
	from openai import AsyncOpenAI
	_client_available = True
except Exception:
	_client_available = False

async def summarize_text(text: str) -> Optional[str]:
	api_key = os.getenv('OPENAI_API_KEY')
	if not _client_available or not api_key or not text:
		return None
	client = AsyncOpenAI(api_key=api_key)
	prompt = (
		"You are a security analyst. Read the recon output and produce a concise, high-signal summary including: "
		"top risks, exposed services, notable subdomains, interesting headers, SSL/WHOIS anomalies, and quick next steps. "
		"Use bullet points. Keep it under 200 words.\n\n" + text
	)
	resp = await client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}], temperature=0.2, max_tokens=300)
	return resp.choices[0].message.content if resp and resp.choices else None
