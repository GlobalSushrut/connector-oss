from tracetramp_client import from_env


def main() -> None:
    client = from_env()
    result = client.chat_completions(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Say hello from TraceTramp cage."}],
    )
    print(result["choices"][0]["message"]["content"])
    print("trace_id:", client.last_headers.get("X-Trace-Id", "-"))
    print("cost_usd:", client.last_headers.get("X-Cost-USD", "-"))


if __name__ == "__main__":
    main()
