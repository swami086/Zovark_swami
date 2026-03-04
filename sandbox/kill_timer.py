import subprocess
import threading
import sys

def enforce_kill_timer(container_name: str, timeout_seconds: int = 30) -> threading.Timer:
    """
    Kills a Docker container after `timeout_seconds` strictly, regardless of 
    what the code inside is doing.
    
    This function spawns a daemonized background timer thread that issues a 
    'docker kill' (SIGKILL) directly to the container so that it cannot delay 
    or trap the termination signal.
    """
    def kill_action():
        print(f"[Timer] 30-second execution limit reached. Force killing container {container_name}...", file=sys.stderr)
        try:
            # We use 'docker kill' instead of 'docker stop'. 
            # 'docker stop' sends SIGTERM and waits for a grace period.
            # 'docker kill' guarantees immediate SIGKILL.
            subprocess.run(
                ["docker", "kill", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception as e:
            print(f"[Timer] Failed to run docker kill for {container_name}: {e}", file=sys.stderr)

    # Note: daemon=True ensures this timer doesn't prevent the main app from exiting
    timer = threading.Timer(interval=timeout_seconds, function=kill_action)
    timer.daemon = True
    timer.start()
    return timer

# --- Usage Example inside the Python Worker ---

if __name__ == "__main__":
    sandbox_container_id = "skill_worker_sandbox_1"
    
    # 1. Start the 30-second kill countdown timer
    kill_timer = enforce_kill_timer(sandbox_container_id, timeout_seconds=30)
    
    try:
        # 2. Execute the user's generated code inside the container
        # Note: Depending on your exact worker loop, this could be blocking or non-blocking.
        # Below represents streaming the execution over Docker Exec.
        process = subprocess.run(
            ["docker", "exec", "-i", sandbox_container_id, "python", "user_code.py"],
            capture_output=True,
            text=True
        )
        print("Sandbox Output:", process.stdout)
        
    finally:
        # 3. Always cancel the timer if the execution finishes before 30 seconds
        kill_timer.cancel()
        
        # 4. Enforce cleanup (Optional: remove the container when done)
        subprocess.run(
            ["docker", "rm", "-f", sandbox_container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
