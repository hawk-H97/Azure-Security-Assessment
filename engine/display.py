"""Display engine — colors, banner, animations, prompts."""
import sys, time, os, threading

class C:
    RESET="\\033[0m"; BOLD="\\033[1m"; DIM="\\033[2m"
    RED="\\033[91m"; GREEN="\\033[92m"; YELLOW="\\033[93m"
    BLUE="\\033[94m"; MAGENTA="\\033[95m"; CYAN="\\033[96m"
    WHITE="\\033[97m"; ORANGE="\\033[38;5;208m"; PURPLE="\\033[38;5;141m"
    TEAL="\\033[38;5;43m"; GOLD="\\033[38;5;220m"
    CRITICAL="\\033[91m"; HIGH="\\033[38;5;208m"; MEDIUM="\\033[93m"; LOW="\\033[92m"

BANNER = r"""
  █████╗ ███████╗██╗   ██╗██████╗ ███████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██╔══██╗╚══███╔╝██║   ██║██╔══██╗██╔════╝    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ███████║  ███╔╝ ██║   ██║██████╔╝█████╗      ███████║██║   ██║██║  ██║██║   ██║
 ██╔══██║ ███╔╝  ██║   ██║██╔══██╗██╔══╝      ██╔══██║██║   ██║██║  ██║██║   ██║
 ██║  ██║███████╗╚██████╔╝██║  ██║███████╗    ██║  ██║╚██████╔╝██████╔╝██║   ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
"""

HAWK = r"""
                         __
                        /  \
                       / /\ \
                      / / /\ \
                 .---/ / /--\ \---.
                /   \ \_\   / /   \
               /  \  \__\ / /  /  \
              / /\ \      V  / /\ \
             / /  \/  /\  | / /  \ \
            /_/    \ /  \_|/ /    \_\
                    Y      Y
                    |  🦅  |
                    |      |
"""

SHIELD = """
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║    🛡  AZURE AUDIT PRO  v1                                           ║
  ║                                                                      ║
  ║    20 Azure Services  ·  120+ Checks  ·  8 Compliance Frameworks    ║
  ║    CIS · NIST CSF · NIST 800-53 · CSA CCM · MITRE · HIPAA · PCI · GDPR ║
  ║                                                                      ║
  ║    Developed by  🦅  SINGARAM                                        ║
  ║    Azure Security Assessment Tool                                    ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
"""

class Display:
    def __init__(self):
        self._spin   = False
        self._thread = None

    def info(self, msg):    print(f"  \033[96mℹ\033[0m  {msg}")
    def success(self, msg): print(f"  \033[92m✔\033[0m  \033[92m{msg}\033[0m")
    def warn(self, msg):    print(f"  \033[93m⚠\033[0m  \033[93m{msg}\033[0m")
    def error(self, msg):   print(f"  \033[91m✖\033[0m  \033[91m{msg}\033[0m")
    def dim(self, msg):     print(f"  \033[2m{msg}\033[0m")

    def section(self, title):
        w = 72
        print(f"\n  \033[94m{'─'*w}\033[0m")
        print(f"  \033[1m\033[94m  {title}\033[0m")
        print(f"  \033[94m{'─'*w}\033[0m")

    def subsection(self, title):
        print(f"\n  \033[38;5;43m┌─ {title}\033[0m")

    def prompt(self, question, default=None):
        if default is not None:
            q = f"\n  \033[38;5;220m❓\033[0m  \033[1m{question}\033[0m  \033[2m[default: {default}]\033[0m\n  \033[38;5;220m▸\033[0m  "
        else:
            q = f"\n  \033[38;5;220m❓\033[0m  \033[1m{question}\033[0m\n  \033[38;5;220m▸\033[0m  "
        try:
            val = input(q)
            return val if val.strip() else (default or "")
        except EOFError:
            return default or ""

    def prompt_secret(self, label):
        q = f"\n  \033[38;5;220m🔑\033[0m  \033[1m{label}\033[0m\n  \033[38;5;220m▸\033[0m  "
        try:
            return input(q)
        except EOFError:
            return ""

    def progress_bar(self, current, total, label=""):
        pct    = current / max(total, 1)
        filled = int(pct * 32)
        bar    = "\033[92m" + "█" * filled + "\033[2m" + "░" * (32 - filled) + "\033[0m"
        sys.stdout.write(f"\r  {bar}  \033[96m{int(pct*100):3d}%\033[0m  {label[:50]:<50}")
        sys.stdout.flush()
        if current >= total:
            print()

    def print_check_result(self, check_id, resource, sev, status, region):
        col = {
            "Critical": "\033[91m", "High": "\033[38;5;208m",
            "Medium":   "\033[93m", "Low":  "\033[92m",
        }.get(sev, "\033[91m")
        print(f"  {col}✖\033[0m  \033[2m{region:20}\033[0m  "
              f"\033[96m{check_id:42}\033[0m  "
              f"{col}\033[1m[{sev}]\033[0m  "
              f"\033[2m{resource[:45]}\033[0m")

    def start_spinner(self, msg="Working"):
        self._spin = True
        def _s():
            frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
            i = 0
            while self._spin:
                sys.stdout.write(f"\r  \033[96m{frames[i%len(frames)]}\033[0m  {msg}...")
                sys.stdout.flush()
                time.sleep(0.08)
                i += 1
            sys.stdout.write("\r" + " " * (len(msg) + 20) + "\r")
            sys.stdout.flush()
        self._thread = threading.Thread(target=_s, daemon=True)
        self._thread.start()

    def stop_spinner(self):
        self._spin = False
        if self._thread:
            self._thread.join(timeout=1)

    def banner(self):
        os.system("clear" if os.name != "nt" else "cls")
        print(f"\033[38;5;220m{HAWK}\033[0m")
        print(f"\033[96m\033[1m{BANNER}\033[0m")
        print(f"\033[93m{SHIELD}\033[0m")
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  \033[2m{'─'*72}\033[0m")
        print(f"  \033[1mVersion:\033[0m   \033[92m1.0.0\033[0m        "
              f"\033[1mDate:\033[0m \033[96m{now}\033[0m")
        print(f"  \033[1mServices:\033[0m  \033[38;5;208m20 Azure Services\033[0m  "
              f"\033[1mChecks:\033[0m \033[38;5;141m120+ security checks\033[0m")
        print(f"  \033[1mDeveloper:\033[0m \033[38;5;220m🦅 Singaram\033[0m      "
              f"\033[1mTool:\033[0m \033[38;5;43mAzure Security Assessment\033[0m")
        print(f"  \033[2m{'─'*72}\033[0m\n")
        self._animate_intro()

    def _animate_intro(self):
        msg = "  🦅  Initializing Azure Audit Pro v1 by Singaram"
        sys.stdout.write(f"\n\033[96m{msg}\033[0m")
        sys.stdout.flush()
        for _ in range(3):
            for dot in [".", ".", "."]:
                time.sleep(0.12)
                sys.stdout.write(f"\033[96m{dot}\033[0m")
                sys.stdout.flush()
        time.sleep(0.2)
        sys.stdout.write(f"  \033[92mREADY ✓\033[0m\n\n")
        sys.stdout.flush()
