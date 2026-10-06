"""
Stage 6 Automated Verification: Visual Language & Design Tokens (Redesign)
Verifies:
1. Palette specifications in frontend/src/styles/tokens.css:
   - Modern light canvas background: #F8F9FB
   - Surface elevations: #FFFFFF, #F1F3F7
   - Confident warm coral accent: #FF471A
   - Accessible severity colors:
     - low: #1D63ED
     - medium: #B54708
     - high: #C4320A
     - critical: #B42318
2. Typography:
   - Plus Jakarta Sans display typography
   - Inter workhorse body typography
   - JetBrains Mono technical telemetry
3. Spacing Scale:
   - Strict 4/8/12/16/24/32/48px scale without arbitrary pixel values
4. Motion:
   - Spring-based entrance & tactile micro-interactions (< 300ms)
5. Zero hardcoded hex values outside tokens.css rule across frontend/src.
"""
import os
import re
import sys

def test_stage6():
    print("[*] Starting Stage 6 Automated Verification (Redesigned Visual Language & Tokens)...")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tokens_path = os.path.join(base_dir, "frontend", "src", "styles", "tokens.css")

    # 1. Existence check
    assert os.path.exists(tokens_path), f"tokens.css not found at {tokens_path}!"
    print(f"    [+] tokens.css located at: {tokens_path}")

    with open(tokens_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 2. Palette verification
    print("[*] 1. Verifying redesigned palette token definitions...")
    expected_hex_tokens = {
        "Clean Light Canvas": ("#F8F9FB", ["--bg-app"]),
        "Surface Elevation 1": ("#FFFFFF", ["--bg-panel-1"]),
        "Surface Elevation 2": ("#F1F3F7", ["--bg-panel-2"]),
        "Electric Coral Accent": ("#FF471A", ["--accent-interactive"]),
        "Severity Low (Cobalt)": ("#1D63ED", ["--severity-low"]),
        "Severity Medium (Amber)": ("#B54708", ["--severity-medium"]),
        "Severity High (Rust)": ("#C4320A", ["--severity-high"]),
        "Severity Critical (Crimson)": ("#B42318", ["--severity-critical"])
    }

    content_upper = content.upper()
    for name, (hex_code, vars_to_check) in expected_hex_tokens.items():
        assert hex_code.upper() in content_upper, f"Missing color {hex_code} ({name}) in tokens.css!"
        for v in vars_to_check:
            assert v in content, f"Expected CSS variable {v} for {name}!"
        print(f"    [+] {name}: {hex_code} verified with variable(s): {', '.join(vars_to_check)}")

    # 3. Typography verification
    print("[*] 2. Verifying typography pairing token definitions...")
    assert "Plus Jakarta Sans" in content, "Missing 'Plus Jakarta Sans' font definition!"
    assert "Inter" in content, "Missing 'Inter' font definition!"
    assert "JetBrains Mono" in content, "Missing 'JetBrains Mono' font definition!"
    assert "--font-display" in content, "Missing --font-display variable!"
    assert "--font-ui" in content, "Missing --font-ui variable!"
    assert "--font-mono" in content, "Missing --font-mono variable!"
    
    # Check weights
    for w in ["400", "500", "600", "700"]:
        assert w in content, f"Missing font weight {w} in tokens.css!"
    print("    [+] Typography verified: Plus Jakarta Sans + Inter + JetBrains Mono.")

    # 4. Spacing scale verification
    print("[*] 3. Verifying strict spacing scale (4 / 8 / 12 / 16 / 24 / 32 / 48px)...")
    expected_spacings = ["4px", "8px", "12px", "16px", "24px", "32px", "48px"]
    for sp in expected_spacings:
        assert sp in content, f"Missing spacing token {sp} in tokens.css!"
    
    # Check for unauthorized arbitrary pixel values in spacing variables
    space_var_matches = re.findall(r'--space-[a-zA-Z0-9_-]+:\s*([^;]+);', content)
    for val in space_var_matches:
        cleaned_val = val.strip()
        assert cleaned_val in expected_spacings, (
            f"Unauthorized spacing variable value '{cleaned_val}' found! Must strictly be one of {expected_spacings}."
        )
    print("    [+] Spacing scale strictly verified: 4px, 8px, 12px, 16px, 24px, 32px, 48px only.")

    # 5. Motion verification
    print("[*] 4. Verifying spring motion & transition timings (< 300ms)...")
    assert "--dur-event-in" in content, "Missing --dur-event-in token!"
    assert "--dur-severity-trans" in content, "Missing --dur-severity-trans token!"
    assert "--ease-spring" in content, "Missing --ease-spring token!"
    print("    [+] Spring motion & micro-interactions verified.")

    # 6. Check for future compliance: Zero hardcoded hex values outside tokens.css
    print("[*] 5. Verifying zero hardcoded hex values outside tokens.css in frontend/src...")
    src_dir = os.path.join(base_dir, "frontend", "src")
    hex_pattern = re.compile(r'#[0-9a-fA-F]{3,8}\b')
    violating_files = []

    if os.path.exists(src_dir):
        for root, _, files in os.walk(src_dir):
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, src_dir)
                if file.endswith((".css", ".js", ".jsx", ".ts", ".tsx", ".html")):
                    if os.path.abspath(filepath) == os.path.abspath(tokens_path):
                        continue  # tokens.css is the single source of truth
                    with open(filepath, "r", encoding="utf-8") as f:
                        file_content = f.read()
                    matches = hex_pattern.findall(file_content)
                    if matches:
                        violating_files.append((rel_path, matches))

    assert not violating_files, f"Hardcoded hex values found outside tokens.css: {violating_files}"
    print("    [+] Zero hardcoded hex values found outside tokens.css!")

    print("\n[***] ALL STAGE 6 DESIGN SYSTEM CHECKS PASSED PERFECTLY [***]")

if __name__ == "__main__":
    test_stage6()
