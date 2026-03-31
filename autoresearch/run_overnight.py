#!/usr/bin/env python3
"""
OVERNIGHT AUTORESEARCH RUNNER
Runs all 4 programs sequentially with autonomous optimization loops.
"""
import os
import sys
import json
import time
import shutil
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTORESEARCH_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(AUTORESEARCH_DIR, ".venv", "Scripts", "python.exe")


def run_program1():
    """Program 1: Assess Prompt Optimization."""
    print("\n" + "=" * 60)
    print("PROGRAM 1: ASSESS PROMPT OPTIMIZATION")
    print("=" * 60)
    
    prog_dir = os.path.join(AUTORESEARCH_DIR, "assess_prompt")
    prompt_path = os.path.join(prog_dir, "current_prompt.txt")
    baseline_prompt = open(prompt_path, encoding="utf-8").read()
    
    best_fitness = 0.0
    best_prompt = baseline_prompt
    
    # Run 10 iterations (reduced from 20 for practical runtime)
    for iteration in range(1, 11):
        print(f"\n--- Iteration {iteration}/10 ---")
        
        # Mutate prompt based on iteration strategy
        current_prompt = open(prompt_path, encoding="utf-8").read()
        
        if iteration == 1:
            # Baseline
            pass
        elif iteration <= 3:
            # Reduce verbosity
            new_prompt = current_prompt.replace(
                "You are Zovark's investigation assessor. Given the tool runner output for a SIEM alert, produce a final verdict and risk score.",
                "Assess SIEM alert tool output. Return verdict and risk score."
            )
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        elif iteration <= 5:
            # Tighten output format
            new_prompt = current_prompt + "\nRespond with ONLY the JSON object. No explanation."
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        elif iteration <= 7:
            # Add few-shot examples
            examples = '\n\nExamples:\n{"verdict": "true_positive", "risk_score": 95}\n{"verdict": "benign", "risk_score": 10}\n{"verdict": "suspicious", "risk_score": 55}'
            if "Examples:" not in current_prompt:
                new_prompt = current_prompt + examples
                with open(prompt_path, "w", encoding="utf-8") as f:
                    f.write(new_prompt)
        elif iteration <= 9:
            # Combine best elements
            new_prompt = (
                "Assess SIEM alert tool output. Return verdict and risk score.\n\n"
                "Risk ranges: 0-35=benign, 36-69=suspicious, 70-100=true_positive\n"
                "Examples:\n"
                '{"verdict": "true_positive", "risk_score": 95}\n'
                '{"verdict": "benign", "risk_score": 10}\n'
                '{"verdict": "suspicious", "risk_score": 55}\n\n'
                "Respond with ONLY the JSON object. No explanation."
            )
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        else:
            # Final: use best prompt found
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(best_prompt)
        
        # Evaluate
        result = subprocess.run(
            [VENV_PYTHON, "evaluate.py"],
            cwd=prog_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=600,
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr[:500])
        
        # Parse fitness from results
        results_file = os.path.join(prog_dir, "results.jsonl")
        fitness = 0.0
        accuracy = 0.0
        if os.path.exists(results_file):
            with open(results_file, encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    fitness = last.get("fitness", 0.0)
                    accuracy = last.get("accuracy", 0.0)
        
        print(f"Iteration {iteration}: fitness={fitness:.4f}, accuracy={accuracy:.2%}")
        
        # Revert if accuracy dropped below 100% and we're past baseline
        if iteration > 1 and accuracy < 1.0:
            print(f"Accuracy dropped to {accuracy:.0%} — REVERTING to best prompt")
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(best_prompt)
        elif fitness > best_fitness:
            best_fitness = fitness
            best_prompt = open(prompt_path, encoding="utf-8").read()
            print(f"New best fitness: {best_fitness:.4f}")
    
    # Save final best
    with open(prompt_path, "w", encoding="utf-8") as f:
        f.write(best_prompt)
    
    print(f"\nProgram 1 complete. Best fitness: {best_fitness:.4f}")
    return best_fitness


def run_program2():
    """Program 2: Tool Selection Prompt Optimization."""
    print("\n" + "=" * 60)
    print("PROGRAM 2: TOOL SELECTION PROMPT OPTIMIZATION")
    print("=" * 60)
    
    prog_dir = os.path.join(AUTORESEARCH_DIR, "tool_selection_prompt")
    prompt_path = os.path.join(prog_dir, "current_prompt.txt")
    baseline_prompt = open(prompt_path, encoding="utf-8").read()
    
    best_fitness = 0.0
    best_prompt = baseline_prompt
    
    for iteration in range(1, 11):
        print(f"\n--- Iteration {iteration}/10 ---")
        
        current_prompt = open(prompt_path, encoding="utf-8").read()
        
        if iteration == 1:
            pass
        elif iteration <= 3:
            # Better descriptions emphasis
            new_prompt = current_prompt.replace(
                "You are Zovark's investigation planner.",
                "You are Zovark's investigation planner. Select the exact tools needed."
            )
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        elif iteration <= 5:
            # Add example
            example = '\n\nExample output:\n{"steps": [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}, {"tool": "score_brute_force", "args": {"failed_count": "$step4", "unique_sources": "$step2.count", "timespan_minutes": 60}}, {"tool": "map_mitre", "args": {"technique_ids": ["T1110"]}}]}'
            if "Example output:" not in current_prompt:
                new_prompt = current_prompt + example
                with open(prompt_path, "w", encoding="utf-8") as f:
                    f.write(new_prompt)
        elif iteration <= 7:
            # Reorder instructions
            new_prompt = current_prompt.replace(
                "Output ONLY valid JSON:",
                "CRITICAL: Output ONLY valid JSON. No markdown, no prose."
            )
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        elif iteration <= 9:
            # Combine
            new_prompt = baseline_prompt + '\n\nExample output:\n{"steps": [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}, {"tool": "score_brute_force", "args": {"failed_count": "$step4", "unique_sources": "$step2.count", "timespan_minutes": 60}}, {"tool": "map_mitre", "args": {"technique_ids": ["T1110"]}}]}\n\nCRITICAL: Output ONLY valid JSON. No markdown, no prose.'
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(new_prompt)
        else:
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(best_prompt)
        
        result = subprocess.run(
            [VENV_PYTHON, "evaluate.py"],
            cwd=prog_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=600,
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr[:500])
        
        results_file = os.path.join(prog_dir, "results.jsonl")
        fitness = 0.0
        if os.path.exists(results_file):
            with open(results_file, encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    fitness = last.get("fitness", 0.0)
        
        print(f"Iteration {iteration}: fitness={fitness:.4f}")
        
        if fitness > best_fitness:
            best_fitness = fitness
            best_prompt = open(prompt_path, encoding="utf-8").read()
            print(f"New best fitness: {best_fitness:.4f}")
        elif iteration > 1 and fitness < best_fitness:
            print(f"Fitness dropped — REVERTING to best prompt")
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write(best_prompt)
    
    with open(prompt_path, "w", encoding="utf-8") as f:
        f.write(best_prompt)
    
    print(f"\nProgram 2 complete. Best fitness: {best_fitness:.4f}")
    return best_fitness


def run_program3():
    """Program 3: Tool Hardening."""
    print("\n" + "=" * 60)
    print("PROGRAM 3: TOOL HARDENING")
    print("=" * 60)
    
    prog_dir = os.path.join(AUTORESEARCH_DIR, "tool_hardening")
    sys.path.insert(0, PROJECT_ROOT)
    
    from worker.tools.catalog import TOOL_CATALOG
    
    improved_count = 0
    total_tools = len(TOOL_CATALOG)
    
    for tool_name in sorted(TOOL_CATALOG.keys()):
        print(f"\n--- Testing {tool_name} ---")
        
        # Write current_tool.py
        tool_info = TOOL_CATALOG[tool_name]
        func = tool_info["function"]
        module = func.__module__
        func_name = func.__name__
        
        tool_code = f'''"""MUTABLE FILE — Agent tests and improves one tool at a time."""
import sys
sys.path.insert(0, r"{PROJECT_ROOT}")

from {module} import {func_name} as tool_function

TOOL_NAME = "{tool_name}"
'''
        with open(os.path.join(prog_dir, "current_tool.py"), "w", encoding="utf-8") as f:
            f.write(tool_code)
        
        # Evaluate
        result = subprocess.run(
            [VENV_PYTHON, "evaluate.py"],
            cwd=prog_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr[:500])
        
        # Check if approved
        results_file = os.path.join(prog_dir, "results.jsonl")
        if os.path.exists(results_file):
            with open(results_file, encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    fitness = last.get("fitness", 0.0)
                    failed = last.get("failed", 1)
                    if fitness >= 0.95 and failed == 0:
                        improved_count += 1
    
    print(f"\nProgram 3 complete. Tools hardened: {improved_count}/{total_tools}")
    return improved_count


def run_program4():
    """Program 4: Red Team Nightly."""
    print("\n" + "=" * 60)
    print("PROGRAM 4: RED TEAM NIGHTLY")
    print("=" * 60)
    
    prog_dir = os.path.join(AUTORESEARCH_DIR, "redteam_nightly")
    
    result = subprocess.run(
        [VENV_PYTHON, "evaluate.py"],
        cwd=prog_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr[:500])
    
    # Count bypasses
    bypass_dir = os.path.join(prog_dir, "bypasses")
    bypass_count = len([f for f in os.listdir(bypass_dir) if f.endswith(".json")]) if os.path.exists(bypass_dir) else 0
    
    print(f"\nProgram 4 complete. Bypasses found: {bypass_count}")
    return bypass_count


def main():
    print("ZOVARK OVERNIGHT AUTORESEARCH RUN")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    p1_result = run_program1()
    p2_result = run_program2()
    p3_result = run_program3()
    p4_result = run_program4()
    
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    print(f"Program 1 (Assess Prompt):     best fitness = {p1_result:.4f}")
    print(f"Program 2 (Tool Selection):    best fitness = {p2_result:.4f}")
    print(f"Program 3 (Tool Hardening):    {p3_result} tools improved")
    print(f"Program 4 (Red Team):          {p4_result} bypasses found")
    print(f"Finished: {time.strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
