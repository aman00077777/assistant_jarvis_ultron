import os
import sys
from dotenv import load_dotenv
from google import genai

# Load environment variables from .env file
load_dotenv()

def main():
    model_name = os.getenv("ASSISTANT_MODEL")
    if not model_name:
        print("Error: ASSISTANT_MODEL environment variable set nahi hai.", file=sys.stderr)
        sys.exit(1)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable set nahi hai.", file=sys.stderr)
        sys.exit(1)

    # Initialize Gemini client without hardcoding or logging the key
    client = genai.Client(api_key=api_key)

    # Send a one-line "hello" prompt
    response = client.models.generate_content(
        model=model_name,
        contents="Hello",
    )

    if response and response.text:
        print(response.text)
    else:
        print("No text received in response.")

if __name__ == "__main__":
    main()
