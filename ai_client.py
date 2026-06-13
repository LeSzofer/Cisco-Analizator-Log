from __future__ import annotations

import json
import urllib.request
import urllib.error

class AIClient:
    config: dict = {}

    @classmethod
    def set_config(cls, config: dict) -> None:
        cls.config = config

    @classmethod
    def generate(cls, prompt: str, system_instruction: str = "") -> str:
        cfg = cls.config
        provider = cfg.get("provider", "ollama")
        api_key = cfg.get("api_key", "")
        api_url = cfg.get("api_url", "").rstrip("/")
        model = cfg.get("model", "")

        # Domyślne modele jeśli nie określono
        if not model:
            if provider == "gemini":
                model = "gemini-2.5-flash"
            elif provider == "ollama":
                model = "llama3"
            else:
                model = "local-model"

        try:
            if provider == "gemini":
                if not api_key:
                    return "Błąd: Brak klucza API Gemini. Wprowadź go w zakładce Ustawienia (Settings)."
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                
                full_prompt = prompt
                if system_instruction:
                    full_prompt = f"{system_instruction}\n\nUżytkownik pyta/Zdarzenie do analizy:\n{prompt}"
                
                data = {
                    "contents": [{
                        "parts": [{"text": full_prompt}]
                    }]
                }
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    return text

            elif provider == "ollama":
                url = f"{api_url}/api/chat"
                messages = []
                if system_instruction:
                    messages.append({"role": "system", "content": system_instruction})
                messages.append({"role": "user", "content": prompt})
                
                data = {
                    "model": model,
                    "messages": messages,
                    "stream": False
                }
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    return res_data["message"]["content"]

            elif provider == "openai":
                url = f"{api_url}/v1/chat/completions"
                messages = []
                if system_instruction:
                    messages.append({"role": "system", "content": system_instruction})
                messages.append({"role": "user", "content": prompt})
                
                data = {
                    "model": model,
                    "messages": messages
                }
                
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode("utf-8"),
                    headers=headers
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    return res_data["choices"][0]["message"]["content"]
            
            else:
                return f"Nieznany dostawca AI: {provider}"

        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode("utf-8")
                return f"Błąd HTTP {e.code} podczas komunikacji z AI: {e.reason}\nSzczegóły: {error_body}"
            except Exception:
                return f"Błąd HTTP {e.code} podczas komunikacji z AI: {e.reason}"
        except Exception as e:
            return f"Błąd połączenia z AI ({provider}): {str(e)}\nUpewnij się, że usługa jest uruchomiona pod adresem {api_url}"
