"""
=====================================================================
 Password Strength Checker  —  Cybersecurity Roadmap: Project 1 of 5
=====================================================================
Roadmap: Password Strength Checker -> File Hash/Integrity Checker ->
         Port Scanner -> Packet Sniffer -> Password Manager

This is a self-contained desktop app. You type (or paste) a password
into ITS OWN input box, and it scores that password live as you type.
Nothing is logged, stored, or sent anywhere.

Why this design, and not "detect passwords anywhere on my system"?
A tool that reads what you type into OTHER apps (browsers, email,
banking apps, the OS login screen, etc.) has to be built with the
same technique as a keylogger: a global keyboard hook that captures
every keystroke on the machine. That's true no matter how good the
intention is - the resulting program is technically indistinguishable
from credential-stealing malware. So we keep the scope to "a tool you
deliberately open and type into" - the same way real password
managers and browser built-in checkers work.

Concepts covered:
  - Shannon entropy (measuring "randomness" in bits)
  - Character-set analysis (upper / lower / digits / symbols)
  - Pattern detection (repeated & sequential & keyboard-walk chars)
  - Dictionary / common-password checks
  - Live GUI feedback (Tkinter event binding)

Run it with:  python3 password_strength_checker.py
(On Linux, if tkinter is missing:  sudo apt-get install python3-tk)
=====================================================================
"""

import math
import re
import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------
# A tiny sample of extremely common passwords, just to demonstrate
# dictionary-based checks. Real-world tools (and step 5 of your
# roadmap!) check against much bigger breached-password databases,
# e.g. via the "Have I Been Pwned" API using k-anonymity.
# ---------------------------------------------------------------
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "111111", "123123", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "football", "password1",
    "qwerty123", "1q2w3e4r", "sunshine", "master", "shadow", "superman",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def char_pool_size(password: str) -> int:
    """Estimate how large the 'alphabet' of possible characters is,
    based on which character types actually appear in the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough estimate for common symbols
    return pool


def shannon_entropy_bits(password: str) -> float:
    """Classic entropy estimate: log2(pool_size) * length.
    More bits = exponentially more guesses an attacker would need."""
    pool = char_pool_size(password)
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detects ascending/descending runs like 'abc', '789', 'cba'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == -1 for j in range(len(chunk) - 1)):
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
    """Detects things like 'qwerty' or 'asdf' - physically adjacent keys."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            if row[i:i + run_length] in lowered:
                return True
    return False


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Detects things like 'aaa' or '111'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """Very rough estimate of offline crack time, assuming a fast
    attacker (~10 billion guesses/sec, roughly a modern GPU rig).
    For intuition only, not a precise security guarantee."""
    if entropy_bits == 0:
        return "instantly"
    try:
        seconds = (2 ** entropy_bits) / guesses_per_second
    except OverflowError:
        return "longer than the age of the universe"

    if seconds < 1:
        return "instantly"

    intervals = [
        ("seconds", 60), ("minutes", 60), ("hours", 24),
        ("days", 365), ("years", 100), ("centuries", None),
    ]
    value = seconds
    unit = "seconds"
    for name, size in intervals:
        unit = name
        if size is None or value < size:
            break
        value /= size
    return f"~{value:,.1f} {unit}"


def analyze_password(password: str) -> dict:
    """Runs all checks and returns a score (0-100), a label, a color,
    the estimated crack time, and a list of improvement tips."""
    if not password:
        return {
            "score": 0, "label": "—", "color": "#888888",
            "crack_time": "-", "tips": ["Start typing to see your score."],
        }

    entropy = shannon_entropy_bits(password)
    tips = []

    if len(password) < 8:
        tips.append("Use at least 8 characters (12+ is much stronger).")
    if not re.search(r"[a-z]", password):
        tips.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        tips.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        tips.append("Add numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        tips.append("Add symbols (e.g. ! @ # $ %).")

    penalty = 0
    if password.lower() in COMMON_PASSWORDS:
        penalty += 50
        tips.append("This is one of the most commonly breached passwords - avoid it entirely.")
    if has_sequential_chars(password):
        penalty += 15
        tips.append("Avoid sequential runs like 'abc' or '123'.")
    if has_keyboard_pattern(password):
        penalty += 15
        tips.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")
    if has_repeated_chars(password):
        penalty += 10
        tips.append("Avoid repeating the same character 3+ times in a row.")

    # Map entropy (roughly 0-80 bits) to a 0-100 score, then apply penalties
    raw_score = min(100, (entropy / 80) * 100)
    score = max(0, round(raw_score - penalty))

    if score < 20:
        label, color = "Very Weak", "#e74c3c"
    elif score < 40:
        label, color = "Weak", "#e67e22"
    elif score < 60:
        label, color = "Fair", "#f1c40f"
    elif score < 80:
        label, color = "Strong", "#2ecc71"
    else:
        label, color = "Very Strong", "#27ae60"

    if not tips:
        tips.append("Great password! No obvious weaknesses detected.")

    return {
        "score": score, "label": label, "color": color,
        "crack_time": estimate_crack_time(entropy), "tips": tips,
    }


class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        root.title("Password Strength Checker")
        root.geometry("480x440")
        root.configure(bg="#1e1e2e")
        root.resizable(False, False)

        self.show_password = tk.BooleanVar(value=False)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", thickness=18)

        tk.Label(
            root, text="Password Strength Checker", font=("Segoe UI", 16, "bold"),
            bg="#1e1e2e", fg="#ffffff",
        ).pack(pady=(20, 5))

        tk.Label(
            root, text="Type a password below — nothing is stored or sent anywhere.",
            font=("Segoe UI", 9), bg="#1e1e2e", fg="#a6adc8",
        ).pack(pady=(0, 15))

        entry_frame = tk.Frame(root, bg="#1e1e2e")
        entry_frame.pack(pady=5)

        self.entry = tk.Entry(
            entry_frame, width=30, font=("Segoe UI", 13), show="*",
            bg="#313244", fg="#ffffff", insertbackground="#ffffff", relief="flat",
        )
        self.entry.pack(side=tk.LEFT, ipady=6, padx=(0, 8))
        self.entry.bind("<KeyRelease>", self.update_score)

        self.score_label = tk.Label(
            root, text="—", font=("Segoe UI", 14, "bold"), bg="#1e1e2e", fg="#888888",
        )
        self.score_label.pack(pady=(15, 5))

        self.progress = ttk.Progressbar(root, style="TProgressbar", length=380, maximum=100, value=0)
        self.progress.pack(pady=5)

        tk.Checkbutton(
            root, text="Show password", variable=self.show_password,
            command=self.toggle_visibility, bg="#1e1e2e", fg="#a6adc8",
            selectcolor="#313244", activebackground="#1e1e2e", activeforeground="#ffffff",
        ).pack(pady=(5, 15))

        tk.Label(
            root, text="Estimated crack time:", font=("Segoe UI", 9, "bold"),
            bg="#1e1e2e", fg="#a6adc8",
        ).pack()
        self.crack_time_label = tk.Label(
            root, text="-", font=("Segoe UI", 10), bg="#1e1e2e", fg="#ffffff",
        )
        self.crack_time_label.pack(pady=(0, 10))

        self.tips_label = tk.Label(
            root, text="Start typing to see your score.", font=("Segoe UI", 9),
            bg="#1e1e2e", fg="#f38ba8", wraplength=420, justify="left",
        )
        self.tips_label.pack(pady=5, padx=20)

    def toggle_visibility(self):
        self.entry.config(show="" if self.show_password.get() else "*")

    def update_score(self, event=None):
        password = self.entry.get()
        result = analyze_password(password)

        self.score_label.config(text=f"{result['label']} ({result['score']}/100)", fg=result["color"])
        self.progress["value"] = result["score"]
        style = ttk.Style()
        style.configure("TProgressbar", background=result["color"])
        self.crack_time_label.config(text=result["crack_time"])
        self.tips_label.config(text="  •  ".join(result["tips"]))


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
