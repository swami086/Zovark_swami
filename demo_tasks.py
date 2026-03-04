import requests
import json
import time

API_URL = "http://localhost:8090/api/v1/tasks"
HEADERS = {
    "Authorization": "Bearer sk-hydra-dev-2026",
    "Content-Type": "application/json"
}
TENANT_ID = "4fed867b-9ac7-4edd-ad78-758980b2e5f1"

PROMPTS = [
    "Write a Python script that reads a CSV string of employee names and salaries, calculates the average salary, finds the highest paid employee, and prints a summary report",
    "Write a Python script that generates a secure random password with uppercase, lowercase, numbers, and symbols, then validates it meets complexity requirements",
    "Write a Python script that takes a list of timestamps and calculates the average time between events, the longest gap, and the shortest gap",
    "Write a Python script that implements a simple calculator supporting add, subtract, multiply, divide with error handling for division by zero",
    "Write a Python script that analyzes a paragraph of text and reports: word count, sentence count, most common word, and average word length"
]

def submit_task(prompt):
    payload = {
        "tenant_id": TENANT_ID,
        "task_type": "code_gen",
        "input": {
            "prompt": prompt
        }
    }
    response = requests.post(API_URL, headers=HEADERS, json=payload)
    if response.status_code == 202:
        print(f"✅ Submitted task: {response.json()['task_id']}")
    else:
        print(f"❌ Failed to submit task: {response.text}")

if __name__ == "__main__":
    for p in PROMPTS:
        submit_task(p)
        time.sleep(1) # stagger to see nice execution timeline
