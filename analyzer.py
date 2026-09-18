import math
import secrets
import string

from pathlib import Path


def analyze_characters(password):
    has_upper = False
    has_lower = False
    has_number = False
    has_symbol = False

    upper_count = 0
    lower_count = 0
    number_count = 0
    symbol_count = 0

    for char in password:
        if char.isupper():
            has_upper = True
            upper_count += 1

        elif char.islower():
            has_lower = True
            lower_count += 1

        elif char.isdigit():
            has_number = True
            number_count += 1

        else:
            has_symbol = True
            symbol_count += 1

    return (
        has_upper,
        has_lower,
        has_number,
        has_symbol,
        upper_count,
        lower_count,
        number_count,
        symbol_count
    )


def detect_patterns(password):
    password_lower = password.lower()

    weak_patterns = [
        "password",
        "123456",
        "abc123",
        "admin",
        "letmein",
        "welcome"
    ]

    found_patterns = []

    for pattern in weak_patterns:
        if pattern in password_lower:
            found_patterns.append(pattern)

    return found_patterns


def detect_repetition(password):
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True

    return False


def detect_sequence(password):
    password_lower = password.lower()

    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789"
    ]

    for sequence in sequences:
        reversed_sequence = sequence[::-1]

        for i in range(len(sequence) - 2):
            forward_piece = sequence[i:i + 3]
            reverse_piece = reversed_sequence[i:i + 3]

            if forward_piece in password_lower:
                return True

            if reverse_piece in password_lower:
                return True

    return False


def detect_keyboard_patterns(password):
    password_lower = password.lower()

    keyboard_patterns = [
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "qwer",
        "asdf",
        "zxcv",
        "qaz",
        "wsx",
        "edc",
        "1qaz",
        "2wsx"
    ]

    found_patterns = []

    for pattern in keyboard_patterns:
        if pattern in password_lower:
            overlapping = False

            for found in found_patterns:
                if pattern in found:
                    overlapping = True
                    break

            if not overlapping:
                found_patterns.append(pattern)

    return found_patterns


def normalize_leetspeak(password):
    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s"
    }

    normalized = password.lower()

    for original, replacement in replacements.items():
        normalized = normalized.replace(
            original,
            replacement
        )

    return normalized


def detect_leetspeak_patterns(password):
    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s"
    }

    password_lower = password.lower()

    if not any(
        char in replacements
        for char in password_lower
    ):
        return []

    normalized_password = normalize_leetspeak(
        password
    )

    common_words = [
        "password",
        "admin",
        "welcome",
        "security",
        "dragon",
        "master",
        "login",
        "secret"
    ]

    found_patterns = []

    for word in common_words:
        if (
            word in normalized_password
            and word not in password_lower
        ):
            found_patterns.append(word)

    return found_patterns


def load_common_passwords():
    file_path = Path(__file__).with_name(
        "common_passwords.txt"
    )

    try:
        with file_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip()
            }

    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = load_common_passwords()


def build_dictionary_words():
    words = set()

    for common_password in COMMON_PASSWORDS:
        candidate = common_password.lower().strip()

        while (
            candidate
            and not candidate[-1].isalpha()
        ):
            candidate = candidate[:-1]

        normalized = normalize_leetspeak(
            candidate
        )

        letters = "".join(
            char
            for char in normalized
            if char.isalpha()
        )

        if len(letters) >= 5:
            words.add(letters)

    return words


DICTIONARY_WORDS = build_dictionary_words()


def detect_common_password(password):
    return password.lower() in COMMON_PASSWORDS


def detect_dictionary_base(password):
    candidate = password.lower().strip()

    while (
        candidate
        and not candidate[-1].isalpha()
    ):
        candidate = candidate[:-1]

    normalized = normalize_leetspeak(
        candidate
    )

    password_letters = "".join(
        char
        for char in normalized
        if char.isalpha()
    )

    if len(password_letters) < 5:
        return []

    if password_letters in DICTIONARY_WORDS:
        return [password_letters]

    return []


def calculate_entropy(
    password,
    has_upper,
    has_lower,
    has_number,
    has_symbol
):
    pool_size = 0

    if has_lower:
        pool_size += 26

    if has_upper:
        pool_size += 26

    if has_number:
        pool_size += 10

    if has_symbol:
        pool_size += 32

    if len(password) > 0 and pool_size > 0:
        return (
            len(password)
            * math.log2(pool_size)
        )

    return 0


def estimate_crack_time(entropy):
    guesses_per_second = 10_000_000_000

    total_combinations = 2 ** entropy
    average_guesses = total_combinations / 2

    seconds = (
        average_guesses
        / guesses_per_second
    )

    minute = 60
    hour = 3600
    day = 86400
    year = 31_536_000

    if seconds < minute:
        return f"{seconds:.2f} seconds"

    if seconds < hour:
        return (
            f"{seconds / minute:.2f} minutes"
        )

    if seconds < day:
        return (
            f"{seconds / hour:.2f} hours"
        )

    if seconds < year:
        return (
            f"{seconds / day:.2f} days"
        )

    years = seconds / year

    if years < 1_000:
        return f"{years:.2f} years"

    if years < 1_000_000:
        return (
            f"{years / 1_000:.2f} thousand years"
        )

    if years < 1_000_000_000:
        return (
            f"{years / 1_000_000:.2f} million years"
        )

    if years < 1_000_000_000_000:
        return (
            f"{years / 1_000_000_000:.2f} billion years"
        )

    return "> 1 trillion years"


def calculate_base_score(
    password,
    has_upper,
    has_lower,
    has_number,
    has_symbol
):
    score = 0

    if len(password) >= 12:
        score += 30

    elif len(password) >= 8:
        score += 20

    else:
        score += 5

    if has_upper:
        score += 15

    if has_lower:
        score += 15

    if has_number:
        score += 15

    if has_symbol:
        score += 15

    if len(password) >= 16:
        score += 10

    return min(score, 100)


def calculate_penalties(
    found_patterns,
    has_repetition,
    has_sequence,
    keyboard_patterns,
    leetspeak_patterns
):
    penalties = 0

    if found_patterns:
        penalties += min(
            15 * len(found_patterns),
            30
        )

    if has_repetition:
        penalties += 15

    if has_sequence:
        penalties += 15

    if keyboard_patterns:
        penalties += min(
            10 * len(keyboard_patterns),
            20
        )

    if leetspeak_patterns:
        penalties += min(
            15 * len(leetspeak_patterns),
            30
        )

    return penalties


def calculate_score_details(
    password,
    has_upper,
    has_lower,
    has_number,
    has_symbol,
    found_patterns,
    has_repetition,
    has_sequence,
    keyboard_patterns,
    leetspeak_patterns,
    is_common_password,
    dictionary_matches
):
    base_score = calculate_base_score(
        password,
        has_upper,
        has_lower,
        has_number,
        has_symbol
    )

    penalties = calculate_penalties(
        found_patterns,
        has_repetition,
        has_sequence,
        keyboard_patterns,
        leetspeak_patterns
    )

    score_before_caps = max(
        0,
        min(
            base_score - penalties,
            100
        )
    )

    applied_cap = None
    final_score = score_before_caps

    if is_common_password:
        applied_cap = 20
        final_score = min(
            final_score,
            applied_cap
        )

    elif dictionary_matches:
        applied_cap = 50
        final_score = min(
            final_score,
            applied_cap
        )

    return {
        "base_score": base_score,
        "penalties": penalties,
        "score_before_caps": score_before_caps,
        "applied_cap": applied_cap,
        "final_score": final_score
    }


def calculate_score(
    password,
    has_upper,
    has_lower,
    has_number,
    has_symbol,
    found_patterns,
    has_repetition,
    has_sequence,
    keyboard_patterns,
    leetspeak_patterns
):
    base_score = calculate_base_score(
        password,
        has_upper,
        has_lower,
        has_number,
        has_symbol
    )

    penalties = calculate_penalties(
        found_patterns,
        has_repetition,
        has_sequence,
        keyboard_patterns,
        leetspeak_patterns
    )

    return max(
        0,
        min(
            base_score - penalties,
            100
        )
    )


def classify_password(score):
    if score >= 80:
        return "VERY STRONG"

    if score >= 60:
        return "STRONG"

    if score >= 40:
        return "MEDIUM"

    return "WEAK"


def generate_security_issues(
    found_patterns,
    has_repetition,
    has_sequence,
    keyboard_patterns,
    leetspeak_patterns,
    is_common_password,
    dictionary_matches
):
    issues = []

    if found_patterns:
        penalty = min(
            15 * len(found_patterns),
            30
        )

        issues.append(
            f"[-{penalty}] Predictable password pattern detected"
        )

    if has_repetition:
        issues.append(
            "[-15] Repeated characters detected"
        )

    if has_sequence:
        issues.append(
            "[-15] Sequential characters detected"
        )

    if keyboard_patterns:
        penalty = min(
            10 * len(keyboard_patterns),
            20
        )

        issues.append(
            f"[-{penalty}] Keyboard pattern detected"
        )

    if leetspeak_patterns:
        penalty = min(
            15 * len(leetspeak_patterns),
            30
        )

        issues.append(
            f"[-{penalty}] Predictable leetspeak substitution detected"
        )

    if is_common_password:
        issues.append(
            "[CAP 20] Password found in common password list"
        )

    elif dictionary_matches:
        issues.append(
            "[CAP 50] Password is based on a common dictionary word"
        )

    if not issues:
        issues.append(
            "No major security issues detected"
        )

    return issues


def generate_recommendations(
    password,
    has_upper,
    has_lower,
    has_number,
    has_symbol,
    found_patterns,
    has_repetition,
    has_sequence,
    keyboard_patterns,
    leetspeak_patterns,
    is_common_password,
    dictionary_matches
):
    recommendations = []

    if len(password) < 12:
        recommendations.append(
            "Use at least 12 characters"
        )

    if not has_upper:
        recommendations.append(
            "Add at least one uppercase letter"
        )

    if not has_lower:
        recommendations.append(
            "Add at least one lowercase letter"
        )

    if not has_number:
        recommendations.append(
            "Add at least one number"
        )

    if not has_symbol:
        recommendations.append(
            "Add at least one symbol"
        )

    if found_patterns:
        recommendations.append(
            "Avoid common words and predictable password patterns"
        )

    if has_repetition:
        recommendations.append(
            "Avoid repeating the same character several times"
        )

    if has_sequence:
        recommendations.append(
            "Avoid sequential characters such as abc, cba, 123 or 321"
        )

    if keyboard_patterns:
        recommendations.append(
            "Avoid keyboard patterns such as qwerty, asdf or zxcv"
        )

    if leetspeak_patterns:
        recommendations.append(
            "Avoid predictable substitutions such as @ for a, 0 for o, or 3 for e"
        )

    if is_common_password:
        recommendations.append(
            "Do not use passwords found in common password lists"
        )

    if dictionary_matches:
        recommendations.append(
            "Avoid building passwords from common words with predictable numbers or symbols"
        )

    if len(password) < 16:
        recommendations.append(
            "Consider using a longer passphrase for stronger security"
        )

    if not recommendations:
        recommendations.append(
            "No major improvements detected"
        )

    return recommendations


def analyze_password(password):
    (
        has_upper,
        has_lower,
        has_number,
        has_symbol,
        upper_count,
        lower_count,
        number_count,
        symbol_count
    ) = analyze_characters(password)

    found_patterns = detect_patterns(
        password
    )

    has_repetition = detect_repetition(
        password
    )

    has_sequence = detect_sequence(
        password
    )

    keyboard_patterns = detect_keyboard_patterns(
        password
    )

    leetspeak_patterns = detect_leetspeak_patterns(
        password
    )

    is_common_password = detect_common_password(
        password
    )

    dictionary_matches = detect_dictionary_base(
        password
    )

    entropy = calculate_entropy(
        password,
        has_upper,
        has_lower,
        has_number,
        has_symbol
    )

    crack_time = estimate_crack_time(
        entropy
    )

    score_details = calculate_score_details(
        password,
        has_upper,
        has_lower,
        has_number,
        has_symbol,
        found_patterns,
        has_repetition,
        has_sequence,
        keyboard_patterns,
        leetspeak_patterns,
        is_common_password,
        dictionary_matches
    )

    score = score_details[
        "final_score"
    ]

    strength = classify_password(
        score
    )

    security_issues = generate_security_issues(
        found_patterns,
        has_repetition,
        has_sequence,
        keyboard_patterns,
        leetspeak_patterns,
        is_common_password,
        dictionary_matches
    )

    recommendations = generate_recommendations(
        password,
        has_upper,
        has_lower,
        has_number,
        has_symbol,
        found_patterns,
        has_repetition,
        has_sequence,
        keyboard_patterns,
        leetspeak_patterns,
        is_common_password,
        dictionary_matches
    )

    return {
        "length": len(password),
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "crack_time": crack_time,

        "score_details": score_details,

        "character_types": {
            "uppercase": has_upper,
            "lowercase": has_lower,
            "numbers": has_number,
            "symbols": has_symbol
        },

        "character_counts": {
            "uppercase": upper_count,
            "lowercase": lower_count,
            "numbers": number_count,
            "symbols": symbol_count
        },

        "security_checks": {
            "weak_patterns": found_patterns,
            "keyboard_patterns": keyboard_patterns,
            "leetspeak_patterns": leetspeak_patterns,
            "common_password": is_common_password,
            "dictionary_matches": dictionary_matches,
            "repetition": has_repetition,
            "sequence": has_sequence
        },

        "security_issues": security_issues,
        "recommendations": recommendations
    }


def generate_password(
    length=16,
    max_attempts=1000
):
    if length < 12:
        length = 12

    characters = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
    )

    for _ in range(max_attempts):
        password_chars = [
            secrets.choice(
                string.ascii_lowercase
            ),
            secrets.choice(
                string.ascii_uppercase
            ),
            secrets.choice(
                string.digits
            ),
            secrets.choice(
                string.punctuation
            )
        ]

        for _ in range(length - 4):
            password_chars.append(
                secrets.choice(
                    characters
                )
            )

        secrets.SystemRandom().shuffle(
            password_chars
        )

        password = "".join(
            password_chars
        )

        result = analyze_password(
            password
        )

        checks = result[
            "security_checks"
        ]

        if (
            result["score"] >= 80
            and not checks["weak_patterns"]
            and not checks["keyboard_patterns"]
            and not checks["leetspeak_patterns"]
            and not checks["common_password"]
            and not checks["dictionary_matches"]
            and not checks["repetition"]
            and not checks["sequence"]
        ):
            return password

    raise RuntimeError(
        "Unable to generate a password matching the security criteria"
    )