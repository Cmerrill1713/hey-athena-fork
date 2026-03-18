"""Shell command safety and classification module for the Athena project.

Provides functions to classify text blocks, detect dangerous patterns,
validate shell plans, and guard against unsafe execution.

All functions are pure (no side effects, no file I/O).
"""

import re
from typing import Optional


KNOWN_COMMANDS = frozenset({
    "cd", "ls", "cat", "grep", "rm", "cp", "mv", "mkdir", "chmod", "chown",
    "echo", "export", "source", "alias", "set", "unset", "pwd", "which",
    "find", "awk", "sed", "sort", "uniq", "wc", "head", "tail", "touch",
    "ln", "tar", "curl", "wget", "ssh", "scp", "rsync", "docker", "pip",
    "npm", "python3", "python", "bash", "sh", "systemctl", "journalctl",
    "apt-get", "brew", "git", "make", "cmake", "yarn", "node", "go",
    "rustc", "cargo",
})

PATH_PREFIXES = ("/bin/", "/usr/", "/sbin/", "/opt/", "/tmp/", "/var/", "~/")

HEREDOC_PATTERN = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")

INLINE_PYTHON_PATTERN = re.compile(r"python3\s+(-c|<<)")

DESTRUCTIVE_COMMANDS = re.compile(r"\brm\s+-rf\b|\brm\s+-r\b|(?<!>)>(?!>)\s*[^>|]|\bmkfs\b|\bdd\s+if=")

SHELL_SPECIAL_CHARS = re.compile(r"[|&;<>]")

# Prompt paste indicators
_PROMPT_INDICATORS = [
    (re.compile(r"^You are", re.IGNORECASE), "Line starts with 'You are'"),
    (re.compile(r"^Please", re.IGNORECASE), "Line starts with 'Please'"),
    (re.compile(r"As an AI", re.IGNORECASE), "Contains 'As an AI'"),
    (re.compile(r"Your task is", re.IGNORECASE), "Contains 'Your task is'"),
    (re.compile(r"Instructions:", re.IGNORECASE), "Contains 'Instructions:'"),
]

# Shell plan phase keywords
_PHASE_KEYWORDS = {
    "orient": ["orient", "orientation"],
    "inspect": ["inspect", "investigate", "diagnose"],
    "backup": ["backup", "back up"],
    "patch": ["patch", "fix", "repair", "apply"],
    "validate": ["validate", "verify", "test", "check"],
    "rollback": ["rollback", "revert", "restore"],
}

_PHASE_ORDER = ["orient", "inspect", "backup", "patch", "validate", "rollback"]

# Section header pattern: echo statements, # comments, or numbered steps
_SECTION_HEADER = re.compile(r"^(?:\s*(?:echo|#[^#]|\d+\.?)\s*.*?)", re.IGNORECASE)


def _starts_with_command(line: str) -> bool:
    """Check if a line starts with a known shell command, path, or sudo."""
    stripped = line.strip()
    if not stripped:
        return False
    # sudo command
    if stripped.startswith("sudo "):
        after_sudo = stripped[5:].strip()
        first_word = after_sudo.split()[0] if after_sudo else ""
        if first_word in KNOWN_COMMANDS or any(first_word.startswith(p) for p in PATH_PREFIXES):
            return True
    # Direct command
    first_word = stripped.split()[0] if stripped else ""
    if first_word in KNOWN_COMMANDS:
        return True
    # Path prefix
    if any(stripped.startswith(p) for p in PATH_PREFIXES):
        return True
    return False


def _is_sentence_line(line: str) -> bool:
    """Check if a line reads as a prose sentence."""
    stripped = line.strip()
    if not stripped:
        return False
    # Has sentence-ending period (not part of file path or command)
    if stripped.endswith(".") and not SHELL_SPECIAL_CHARS.search(stripped):
        return True
    return False


def _has_shell_chars(text: str) -> bool:
    """Check if text contains shell special characters."""
    return bool(SHELL_SPECIAL_CHARS.search(text))


def classify_block(text: str) -> dict:
    """Classify text as one of: executable_command, prose_only, mixed_unsafe,
    heredoc, inline_python, shell_plan.

    Returns dict with keys: classification (str), confidence (float 0-1),
    reasons (list[str]).
    """
    if not text or not text.strip():
        return {
            "classification": "prose_only",
            "confidence": 0.5,
            "reasons": ["Empty input"],
        }

    lines = text.split("\n")
    non_empty_lines = [l for l in lines if l.strip()]

    # Check if comment-only
    comment_lines = [l for l in non_empty_lines if l.strip().startswith("#")]
    if non_empty_lines and len(comment_lines) == len(non_empty_lines):
        return {
            "classification": "prose_only",
            "confidence": 0.9,
            "reasons": ["Comment-only input"],
        }

    # Priority 1: heredoc
    heredoc_matches = HEREDOC_PATTERN.findall(text)
    if heredoc_matches:
        return {
            "classification": "heredoc",
            "confidence": 0.9,
            "reasons": [f"Heredoc delimiter(s) found: {', '.join(heredoc_matches)}"],
        }

    # Priority 2: inline_python
    if INLINE_PYTHON_PATTERN.search(text):
        return {
            "classification": "inline_python",
            "confidence": 0.9,
            "reasons": ["Inline python3 invocation detected"],
        }

    # Priority 3: shell_plan
    phases_found = []
    for phase_name, keywords in _PHASE_KEYWORDS.items():
        for keyword in keywords:
            for line in non_empty_lines:
                stripped = line.strip().lower()
                # Check if keyword appears in a section header context
                if _SECTION_HEADER.match(line) and keyword in stripped:
                    if phase_name not in phases_found:
                        phases_found.append(phase_name)
                    break
            else:
                continue
            break

    if len(phases_found) >= 3:
        return {
            "classification": "shell_plan",
            "confidence": 0.85,
            "reasons": [f"Shell plan phases detected: {', '.join(phases_found)}"],
        }

    # Priority 4: executable_command
    for line in lines:
        if _starts_with_command(line):
            return {
                "classification": "executable_command",
                "confidence": 0.9,
                "reasons": [f"Line starts with recognized command: {line.strip()[:60]}"],
            }

    # Priority 5: mixed_unsafe
    has_sentence = any(_is_sentence_line(l) for l in non_empty_lines)
    has_command_like = any(
        _starts_with_command(l) or _has_shell_chars(l)
        for l in non_empty_lines
        if l.strip() and not l.strip().startswith("#")
    )
    # Also check for $ prefix
    has_dollar = any(l.strip().startswith("$") for l in non_empty_lines)
    # Check for commands embedded within prose lines
    has_embedded_command = False
    for line in non_empty_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        words = stripped.split()
        for word in words:
            # Strip trailing punctuation for matching
            clean = re.sub(r'[.,;:!?]$', '', word)
            if clean in KNOWN_COMMANDS:
                has_embedded_command = True
                break
            if any(clean.startswith(p) for p in PATH_PREFIXES) and '/' in clean[len(p):]:
                has_embedded_command = True
                break
        if has_embedded_command:
            break

    if has_sentence and (has_command_like or has_dollar or has_embedded_command):
        return {
            "classification": "mixed_unsafe",
            "confidence": 0.8,
            "reasons": ["Text mixes prose sentences with command-like constructs"],
        }

    # Priority 6: prose_only (default)
    return {
        "classification": "prose_only",
        "confidence": 0.85,
        "reasons": ["Text reads as prose with no command-like patterns"],
    }


def check_protected_paths(
    text: str, protected_prefixes: list = None
) -> dict:
    """Scan text for references to protected filesystem paths.

    Returns dict with keys: safe (bool), violations (list[dict]).
    Each violation dict has: line_number (int), line (str),
    matched_prefix (str), severity (str).
    """
    if protected_prefixes is None:
        protected_prefixes = [
            "/Users/christianmerrill/Library/LaunchAgents/",
            "/Users/christianmerrill/Library/Application Support/Athena/",
            "/Users/",
        ]

    allowed_paths = ["/Volumes/Untitled/GitHub/", "~/athena"]
    violations = []
    lines = text.split("\n")

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # Check if line ONLY contains allowed paths
        only_allowed = True
        found_allowed = False
        for ap in allowed_paths:
            if ap in stripped:
                found_allowed = True
                remaining = stripped.replace(ap, "")
                remaining = remaining.strip()
                if remaining:
                    only_allowed = False

        if not found_allowed:
            only_allowed = False

        if only_allowed:
            continue

        # Check each protected prefix (order matters - specific first)
        for prefix in protected_prefixes:
            if prefix in stripped:
                # Determine severity
                if "LaunchAgents" in prefix:
                    severity = "critical"
                elif "Application Support/Athena" in prefix:
                    severity = "critical"
                else:
                    severity = "warning"

                violations.append({
                    "line_number": idx,
                    "line": stripped,
                    "matched_prefix": prefix,
                    "severity": severity,
                })
                break  # Only report first (most specific) match per line

    return {
        "safe": len(violations) == 0,
        "violations": violations,
    }


def detect_prompt_paste(text: str) -> dict:
    """Detect when narrative/prompt text was likely pasted into a shell.

    Returns dict with keys: is_prompt_paste (bool), indicators (list[str]),
    confidence (float 0-1).
    """
    indicators = []
    lines = text.split("\n")

    for pattern, description in _PROMPT_INDICATORS:
        # For start-of-line patterns, check each line
        if pattern.pattern.startswith("^"):
            for line in lines:
                if pattern.search(line.strip()):
                    indicators.append(description)
                    break
        else:
            if pattern.search(text):
                indicators.append(description)

    # Check: line ending with colon followed by another prose line
    # Skip lines inside heredoc content (between << delimiter lines)
    heredoc_depth = 0
    heredoc_delim = None
    for i in range(len(lines)):
        stripped = lines[i].strip()
        # Track heredoc boundaries
        if heredoc_depth > 0:
            if stripped == heredoc_delim:
                heredoc_depth = 0
                heredoc_delim = None
            continue  # skip all checks inside heredoc
        if HEREDOC_PATTERN.search(stripped):
            heredoc_depth = 1
            # Extract delimiter
            m = re.search(r"<<\s*'?\?(\w+)" , stripped)
            if m:
                heredoc_delim = m.group(1)
            continue

    # Now do the colon check, skipping heredoc interior lines
    heredoc_depth = 0
    heredoc_delim = None
    for i in range(len(lines) - 1):
        stripped = lines[i].strip()
        # Track heredoc boundaries
        if heredoc_depth > 0:
            if stripped == heredoc_delim:
                heredoc_depth = 0
                heredoc_delim = None
            continue
        if HEREDOC_PATTERN.search(stripped):
            heredoc_depth = 1
            m = re.search(r"<<\s*'?\?(\w+)" , stripped)
            if m:
                heredoc_delim = m.group(1)
            continue

        curr = stripped
        next_line = lines[i + 1].strip()
        if curr.endswith(":") and next_line and not _starts_with_command(next_line):
            # Make sure it's not a label or case statement
            if not curr.startswith("case ") and not curr.endswith("::"):
                indicators.append("Line ending with colon followed by prose line")
                break

    if not indicators:
        return {
            "is_prompt_paste": False,
            "indicators": [],
            "confidence": 0.0,
        }

    confidence = min(0.6 * len(indicators), 0.95)

    return {
        "is_prompt_paste": True,
        "indicators": indicators,
        "confidence": confidence,
    }


def parse_heredoc_blocks(text: str) -> dict:
    """Extract heredoc blocks from text.

    Returns dict with keys: heredocs (list[dict]), is_valid (bool),
    errors (list[str]).
    Each heredoc dict has: delimiter (str), content (str),
    start_line (int), end_line (int).
    """
    heredocs = []
    errors = []
    lines = text.split("\n")
    i = 0

    while i < len(lines):
        match = HEREDOC_PATTERN.search(lines[i])
        if match:
            delimiter = match.group(1)
            start_line = i + 1  # 1-indexed
            content_lines = []
            found_end = False
            j = i + 1

            while j < len(lines):
                if lines[j].strip() == delimiter:
                    found_end = True
                    end_line = j + 1  # 1-indexed
                    heredocs.append({
                        "delimiter": delimiter,
                        "content": "\n".join(content_lines),
                        "start_line": start_line,
                        "end_line": end_line,
                    })
                    i = j + 1
                    break
                else:
                    content_lines.append(lines[j])
                    j += 1

            if not found_end:
                errors.append(
                    f"Unclosed heredoc with delimiter '{delimiter}' "
                    f"starting at line {start_line}"
                )
                i = j
        else:
            i += 1

    is_valid = len(errors) == 0

    return {
        "heredocs": heredocs,
        "is_valid": is_valid,
        "errors": errors,
    }


def parse_inline_python(text: str) -> dict:
    """Detect and extract inline python3 blocks.

    Returns dict with keys: blocks (list[dict]), is_valid (bool),
    errors (list[str]).
    Each block dict has: type (str "-c" or "heredoc"), code (str),
    start_line (int), end_line (int).
    """
    blocks = []
    errors = []
    lines = text.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check for python3 -c '...'
        c_match = re.search(r"python3\s+-c\s+'(.+?)'", line, re.DOTALL)
        if c_match:
            code = c_match.group(1)
            start_line = i + 1
            end_line = i + 1
            # Validate syntax
            try:
                compile(code, "<inline>", "exec")
            except SyntaxError as e:
                errors.append(f"Syntax error in -c block at line {start_line}: {e}")
            blocks.append({
                "type": "-c",
                "code": code,
                "start_line": start_line,
                "end_line": end_line,
            })
            i += 1
            continue

        # Check for python3 << DELIM ... DELIM
        heredoc_match = re.search(r"python3\s+<<-?\s*['\"]?(\w+)['\"]?", line)
        if heredoc_match:
            delimiter = heredoc_match.group(1)
            start_line = i + 1
            content_lines = []
            found_end = False
            j = i + 1

            while j < len(lines):
                if lines[j].strip() == delimiter:
                    found_end = True
                    end_line = j + 1
                    code = "\n".join(content_lines)
                    # Validate syntax
                    try:
                        compile(code, "<inline_heredoc>", "exec")
                    except SyntaxError as e:
                        errors.append(
                            f"Syntax error in heredoc python block at line {start_line}: {e}"
                        )
                    blocks.append({
                        "type": "heredoc",
                        "code": code,
                        "start_line": start_line,
                        "end_line": end_line,
                    })
                    i = j + 1
                    break
                else:
                    content_lines.append(lines[j])
                    j += 1

            if not found_end:
                errors.append(
                    f"Unclosed inline python heredoc with delimiter '{delimiter}' "
                    f"starting at line {start_line}"
                )
                i = j
            continue

        i += 1

    is_valid = len(errors) == 0

    return {
        "blocks": blocks,
        "is_valid": is_valid,
        "errors": errors,
    }


def validate_shell_plan(text: str) -> dict:
    """Validate that shell plan follows order: orient -> inspect -> backup ->
    patch -> validate -> rollback.

    Returns dict with keys: is_valid_plan (bool), phases_found (list[str]),
    missing_phases (list[str]), out_of_order (bool), details (str).
    """
    lines = text.split("\n")
    phases_found = []
    phase_line_numbers = {}

    for idx, line in enumerate(lines):
        stripped = line.strip().lower()
        if not _SECTION_HEADER.match(line):
            continue

        for phase_name in _PHASE_ORDER:
            for keyword in _PHASE_KEYWORDS[phase_name]:
                if keyword in stripped and phase_name not in phase_line_numbers:
                    phase_line_numbers[phase_name] = idx
                    break
            else:
                continue
            break

    phases_found = list(phase_line_numbers.keys())
    missing_phases = [p for p in _PHASE_ORDER if p not in phase_line_numbers]

    # Check ordering
    out_of_order = False
    if len(phases_found) > 1:
        ordered_indices = [phase_line_numbers[p] for p in phases_found]
        if ordered_indices != sorted(ordered_indices):
            out_of_order = True
        else:
            # Also check they follow the canonical phase order
            for i in range(len(phases_found) - 1):
                curr_idx = _PHASE_ORDER.index(phases_found[i])
                next_idx = _PHASE_ORDER.index(phases_found[i + 1])
                if next_idx <= curr_idx:
                    out_of_order = True
                    break

    is_valid_plan = len(missing_phases) == 0 and not out_of_order

    if is_valid_plan:
        details = "All 6 phases present in correct order."
    elif out_of_order:
        details = f"Phases found: {phases_found}. Phases are out of canonical order."
    else:
        details = f"Missing phases: {missing_phases}. Found: {phases_found}."

    return {
        "is_valid_plan": is_valid_plan,
        "phases_found": phases_found,
        "missing_phases": missing_phases,
        "out_of_order": out_of_order,
        "details": details,
    }


def guard(text: str) -> dict:
    """Master function running all safety checks.

    Returns dict with keys: safe_to_execute (bool), classification (dict),
    protected_violations (dict), prompt_paste_detected (dict),
    heredoc_analysis (dict), inline_python_analysis (dict),
    plan_validation (dict), summary (str), recommendations (list[str]).
    """
    classification = classify_block(text)
    protected_violations = check_protected_paths(text)
    prompt_paste_detected = detect_prompt_paste(text)
    heredoc_analysis = parse_heredoc_blocks(text)
    inline_python_analysis = parse_inline_python(text)
    plan_validation = validate_shell_plan(text)

    # Determine safe_to_execute
    executable_classifications = {
        "executable_command", "heredoc", "inline_python", "shell_plan"
    }
    safe_to_execute = (
        classification["classification"] in executable_classifications
        and protected_violations["safe"]
        and not prompt_paste_detected["is_prompt_paste"]
    )

    # Build recommendations
    recommendations = []

    # Destructive command check
    if DESTRUCTIVE_COMMANDS.search(text):
        cls = classification["classification"]
        # Check if there's backup context
        has_backup_context = any(
            kw in text.lower()
            for kw in ["backup", "back up", "bak", "snapshot", "restore"]
        )
        if cls in {"executable_command"} and not has_backup_context:
            recommendations.append(
                "Destructive command detected without backup context. "
                "Consider backing up affected files before proceeding."
            )

    # Mixed unsafe recommendation
    if classification["classification"] == "mixed_unsafe":
        recommendations.append(
            "Text mixes prose with commands. Separate narrative from "
            "executable commands for safe execution."
        )

    # Protected path recommendation
    if not protected_violations["safe"]:
        critical = [v for v in protected_violations["violations"] if v["severity"] == "critical"]
        if critical:
            recommendations.append(
                f"Critical: {len(critical)} protected path violation(s) detected. "
                "Execution blocked."
            )

    # Prompt paste recommendation
    if prompt_paste_detected["is_prompt_paste"]:
        recommendations.append(
            "Prompt/narrative text detected. This does not appear to be "
            "a shell command."
        )

    # Build summary
    if safe_to_execute:
        summary = (
            f"SAFE: Text classified as '{classification['classification']}' "
            f"with no protected path violations or prompt paste indicators."
        )
    else:
        reasons = []
        if classification["classification"] not in executable_classifications:
            reasons.append(
                f"classification is '{classification['classification']}'"
            )
        if not protected_violations["safe"]:
            reasons.append(
                f"{len(protected_violations['violations'])} protected path violation(s)"
            )
        if prompt_paste_detected["is_prompt_paste"]:
            reasons.append("prompt paste detected")
        summary = f"UNSAFE: {'; '.join(reasons)}."

    return {
        "safe_to_execute": safe_to_execute,
        "classification": classification,
        "protected_violations": protected_violations,
        "prompt_paste_detected": prompt_paste_detected,
        "heredoc_analysis": heredoc_analysis,
        "inline_python_analysis": inline_python_analysis,
        "plan_validation": plan_validation,
        "summary": summary,
        "recommendations": recommendations,
    }
