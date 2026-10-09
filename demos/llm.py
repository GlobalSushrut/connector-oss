import time
import requests
from config import DEEPSEEK_KEY, DEEPSEEK_BASE, DEEPSEEK_MODEL, SYSTEM_KNOWLEDGE


class DeepSeekLLM:
    def __init__(self):
        self.total_tokens = 0
        self.total_calls = 0
        self.total_cost = 0.0

    def generate(self, user_prompt: str, max_tokens: int = 2000) -> dict:
        t0 = time.time()
        r = requests.post(
            f"{DEEPSEEK_BASE}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {DEEPSEEK_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": DEEPSEEK_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_KNOWLEDGE},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.7,
            },
            timeout=120,
        )
        elapsed_ms = int((time.time() - t0) * 1000)
        
        # Check for empty response
        if not r.text or len(r.text.strip()) == 0:
            raise ValueError(f"Empty response from DeepSeek API (status: {r.status_code})")
        
        try:
            data = r.json()
        except Exception as e:
            raise ValueError(f"Failed to parse JSON response: {e}. Response text: {r.text[:200]}")
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        prompt_tok = usage.get("prompt_tokens", 0)
        comp_tok = usage.get("completion_tokens", 0)
        total_tok = usage.get("total_tokens", prompt_tok + comp_tok)
        cost = (prompt_tok * 0.00014 + comp_tok * 0.00028) / 1000

        self.total_tokens += total_tok
        self.total_calls += 1
        self.total_cost += cost

        return {
            "content": content,
            "meta": {
                "model": DEEPSEEK_MODEL,
                "prompt_tokens": prompt_tok,
                "completion_tokens": comp_tok,
                "total_tokens": total_tok,
                "cost_usd": round(cost, 6),
                "latency_ms": elapsed_ms,
            },
        }

    def session_stats(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost, 6),
        }
