from flask import Flask, render_template, request, jsonify
import requests, json

app = Flask(__name__)

from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")



def extract_url_features(url):
    """Extracts basic phishing-related features from a URL."""
    features = {
        "url_length": len(url),
        "has_at_symbol": "@" in url,
        "uses_https": url.startswith("https"),
        "dot_count": url.count("."),
        "contains_suspicious_words": any(word in url.lower() for word in 
            ["login", "verify", "account", "bank", "update", "secure"])
    }
    return features

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL"}), 400

    features = extract_url_features(url)

    
    prompt = f"""
    You are a cybersecurity AI. Analyze the following URL for phishing risks.

    URL: {url}
    Extracted Features: {json.dumps(features, indent=2)}

    Evaluate if this URL is likely a phishing attempt.
    Respond in pure JSON only, with these fields:
    {{
      "isPhishing": true or false,
      "confidenceScore": a number between 0 and 100,
      "explanation": "short reason"
    }}
    """

    try:
       
        response = requests.post(
          f"https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent?key={API_KEY}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=10  # 2. Add a timeout for network requests
        )

      
        response.raise_for_status()

        data = response.json()

        
        text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        if not text:
            raise ValueError("AI response was empty or had an unexpected structure.")

       
        cleaned_text = text.strip().strip("```json").strip("```").strip()

        
        result = json.loads(cleaned_text)

        return jsonify(result)

   
    except requests.exceptions.HTTPError as e:
       
        return jsonify({"error": f"API Error: {e.response.status_code} - {e.response.text}"}), 500
    except requests.exceptions.RequestException as e:
     
        return jsonify({"error": f"Network Error: {str(e)}"}), 500
    except json.JSONDecodeError:
       
        return jsonify({"error": "AI analysis failed: Model returned invalid JSON.", "raw_output": text}), 500
    except (KeyError, IndexError, ValueError) as e:
       
        return jsonify({"error": f"AI analysis failed: Unexpected response structure. {str(e)}"}), 500
    except Exception as e:
       
        return jsonify({"error": f"An unknown error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
