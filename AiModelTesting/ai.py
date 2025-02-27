import ollama

def generate_response(prompt):
    model = "llama3.1"  # Ensure this is the correct model name available in your Ollama setup
    response = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}])
    return response["message"]["content"]

if __name__ == "__main__":
    user_input = input("Enter your prompt: ")
    output = generate_response(user_input)
    print("Response:", output)
