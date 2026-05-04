import os
import json
import requests
from dotenv import load_dotenv

# Automatically load keys from your .env file
load_dotenv()

class TriageEngine:
    def __init__(self):
        self.url = os.getenv("AZURE_INFERENCE_ENDPOINT")
        self.az_key = os.getenv("AZURE_INFERENCE_KEY")
        self.mode = "MOCK"

        if self.url and self.az_key and "your" not in self.az_key:
            print(f"[INFO] Connecting to Azure AI Foundry Phi-4 (Direct Web Call)...")
            self.mode = "AZURE_SLM"
        else:
            print("[INFO] Missing live keys. Operating in safe simulation mode.")

    def triage_record(self, record_data, pii_detected):
        """
        Triages the record using a direct web call to the long Azure target URL.
        """
        # --- MOCK MODE ---
        if self.mode == "MOCK":
             return {
                "triage_score": "HIGH (Live Demo)",
                "explanation": "Guardian has flagged this record. The data contains high-risk synthetic Australian medical identifiers alongside names. This violates privacy-by-design baseline policies.",
                "action_required": "Quarantine this data object and route to the Data Quality Officer for manual HITL review."
            }

        # --- PREPARE PROMPT ---
        system_text = "You are Guardian, an AI compliance assistant. Output valid JSON only."
        user_text = f"""
        Analyze this data record for privacy risk.
        
        Record: {json.dumps(record_data)}
        PII Detected: {json.dumps(pii_detected)}
        
        Return a JSON object with keys: 'triage_score' (LOW/MED/HIGH/CRITICAL), 'explanation', and 'action_required'.
        Do not include markdown code block ticks in your response.
        """

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.az_key}"
        }
        
        payload = {
            "model": "Phi-4",
            "messages": [
                {"role": "system", "content": system_text},
                {"role": "user", "content": user_text}
            ],
            "temperature": 0.1
        }

        try:
            response = requests.post(self.url, headers=headers, json=payload)
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
                
            response_data = response.json()
            
            # --- FIXED LINE: Azure Phi-4 returns choices as a list ---
            # We access choices[0] first, then grab the message content!
            raw_content = response_data['choices'][0]['message']['content']
            
            clean_json = raw_content.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_json)

        except Exception as e:
            print(f"[ERROR] Inference failed: {e}")
            return {
                "triage_score": "ERROR",
                "explanation": "AI Inference Service Failed.",
                "action_required": "Check logs or connection."
            }

# Self-test block
if __name__ == "__main__":
    print("--- Running Day 2 Triage Engine ---")
    engine = TriageEngine()
    
    test_record = {"name": "John Citizen", "notes": "Medicare Number: 4123 45678 1"}
    test_pii = ["Australian Medicare Number"]
    
    result = engine.triage_record(test_record, test_pii)
    print(json.dumps(result, indent=2))
