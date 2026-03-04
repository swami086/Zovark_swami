from huggingface_hub import snapshot_download
print("Downloading chat model...")
snapshot_download("Qwen/Qwen2.5-1.5B-Instruct-AWQ", local_dir="/models/chat-model")
print("Chat model done!")
print("Downloading embed model...")
snapshot_download("nomic-ai/nomic-embed-text-v1.5", local_dir="/models/embed-model")
print("Embed model done!")
