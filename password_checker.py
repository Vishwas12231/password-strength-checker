import re
import math

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "admin", "letmein", "welcome"
}

ATTACK_SCENARIOS = {
    "Online Attack (Rate Limited)": 100,
    "Fast Online Attack (No Limit)": 10_000,
    "Single GPU Offline Attack": 10_000_000_000,
    "GPU Cluster (8 GPUs)": 80_000_000_000,
    "Large Botnet / Nation-State": 1_000_000_000_000
}

def calculate_charset(password):
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\\[\]~`]", password):
        charset += 32
    return charset

def calculate_entropy(password):
    charset = calculate_charset(password)
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)

def estimate_crack_time(entropy_bits, guesses_per_second):
    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / guesses_per_second
    return seconds

def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"

def check_patterns(password):
    issues = []
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Common password")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters")
    if re.search(r"(012|123|234|345|456|567|678|789)", password):
        issues.append("Sequential numbers")
    return issues

def password_analysis(password):
    entropy = calculate_entropy(password)
    pattern_issues = check_patterns(password)

    results = {}

    for scenario, speed in ATTACK_SCENARIOS.items():
        seconds = estimate_crack_time(entropy, speed)
        results[scenario] = format_time(seconds)

    return {
        "entropy": round(entropy, 2),
        "issues": pattern_issues,
        "crack_times": results
    }

if __name__ == "__main__":
    pwd = input("Enter password to analyze: ")
    analysis = password_analysis(pwd)

    print("\n--- Password Security Report ---")
    print(f"Estimated Entropy: {analysis['entropy']} bits")

    if analysis["issues"]:
        print("Detected Weaknesses:")
        for issue in analysis["issues"]:
            print(f"- {issue}")

    print("\nEstimated Crack Times:")
    for scenario, time in analysis["crack_times"].items():
        print(f"{scenario}: {time}")
