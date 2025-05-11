from google.cloud.aiplatform_v1 import ModelServiceClient

project_id = "global-wharf-456714-k9"
location = "global"
client = ModelServiceClient()
parent = f"projects/{project_id}/locations/{location}/publishers/google"
try:
    response = client.list_publisher_models(parent=parent)
    print("Modelos disponíveis no Model Garden (Google):")
    for model in response:
        print(f"- {model.name} (Display Name: {model.display_name})")
except Exception as e:
    print(f"Erro ao listar modelos: {str(e)}")