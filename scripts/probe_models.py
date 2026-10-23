import os
import httpx

key = os.environ.get("NVIDIA_API_KEY", "")
H = {"Authorization": "Bearer " + key}
CANDIDATES = [
    "openai/gpt-oss-20b",
    "mistralai/mistral-7b-instruct-v0.3",
    "nvidia/llama-3.1-nemotron-ultra-253b-v1",
    "google/gemma-3-12b-it",
    "nvidia/nemotron-nano-3-30b-a3b",
    "z-ai/glm-5.3-flash",
    "mistralai/mistral-nemo-12b-instruct",
]
for model in CANDIDATES:
    try:
        r = httpx.post("https://integrate.api.nvidia.com/v1/chat/completions", headers=H, timeout=45,
                       json={"model": model, "max_tokens": 4,
                             "messages": [{"role": "user", "content": "hi"}]})
        status = "OK" if r.status_code == 200 else r.text[:90].replace("\n", " ")
        print(f"{model:55s} -> {r.status_code} {status}")
    except Exception as e:
        print(f"{model:55s} -> EXC {type(e).__name__}")
