import os
from google import genai

cliente = genai.Client(api_key=os.getenv('GOOGLE_API_KEY'))

respuesta = cliente.models.generate_content(
    model='gemini-2.0-flash-exp', contents='Donde esta la Torre Eifel?'
)

print(respuesta.text)