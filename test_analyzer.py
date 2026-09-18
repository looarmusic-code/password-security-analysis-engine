from analyzer import (
    analyze_characters,
    detect_patterns,
    detect_repetition,
    detect_sequence,
    detect_keyboard_patterns,
    normalize_leetspeak,
    detect_leetspeak_patterns,
    load_common_passwords,
    detect_common_password,
    detect_dictionary_base,
    calculate_entropy,
    estimate_crack_time,
    calculate_base_score,
    calculate_penalties,
    calculate_score_details,
    calculate_score,
    classify_password,
    generate_security_issues,
    generate_recommendations,
    analyze_password,
    generate_password
)


def test_character_analysis():
    result = analyze_characters("Cyber2026!")

    assert result[0] is True
    assert result[1] is True
    assert result[2] is True
    assert result[3] is True

    assert result[4] == 1
    assert result[5] == 4
    assert result[6] == 4
    assert result[7] == 1


def test_only_lowercase():
    result = analyze_characters("security")

    assert result[0] is False
    assert result[1] is True
    assert result[2] is False
    assert result[3] is False


def test_weak_patterns():
    patterns = detect_patterns(
        "Password123456!"
    )

    assert "password" in patterns
    assert "123456" in patterns


def test_qwerty_not_weak_pattern():
    patterns = detect_patterns(
        "Qwerty2026!"
    )

    assert "qwerty" not in patterns


def test_no_weak_patterns():
    patterns = detect_patterns(
        "G7!xP9@kL2"
    )

    assert patterns == []


def test_repetition():
    assert (
        detect_repetition(
            "SecureAAA2026!"
        )
        is True
    )

    assert (
        detect_repetition(
            "Secure2026!"
        )
        is False
    )


def test_forward_numeric_sequence():
    assert detect_sequence(
        "Cyber123!"
    ) is True


def test_reverse_numeric_sequence():
    assert detect_sequence(
        "Cyber321!"
    ) is True


def test_forward_alphabetical_sequence():
    assert detect_sequence(
        "SecureABC!"
    ) is True


def test_reverse_alphabetical_sequence():
    assert detect_sequence(
        "SecureCBA!"
    ) is True


def test_no_sequence():
    assert detect_sequence(
        "G7!xP9@kL2"
    ) is False


def test_keyboard_pattern():
    patterns = detect_keyboard_patterns(
        "SecureQwerty2026!"
    )

    assert "qwerty" in patterns


def test_multiple_keyboard_patterns():
    patterns = detect_keyboard_patterns(
        "Qwerty-Asdfgh"
    )

    assert "qwerty" in patterns
    assert "asdfgh" in patterns


def test_no_keyboard_pattern():
    patterns = detect_keyboard_patterns(
        "G7!xP9@kL2"
    )

    assert patterns == []


def test_leetspeak_normalization():
    assert (
        normalize_leetspeak(
            "P@ssw0rd"
        )
        == "password"
    )


def test_leetspeak_admin_normalization():
    assert (
        normalize_leetspeak(
            "Adm1n"
        )
        == "admin"
    )


def test_leetspeak_password_detection():
    patterns = detect_leetspeak_patterns(
        "P@ssw0rd!"
    )

    assert "password" in patterns


def test_leetspeak_admin_detection():
    patterns = detect_leetspeak_patterns(
        "Adm1n!"
    )

    assert "admin" in patterns


def test_plain_password_not_leetspeak():
    patterns = detect_leetspeak_patterns(
        "password"
    )

    assert patterns == []


def test_plain_admin_not_leetspeak():
    patterns = detect_leetspeak_patterns(
        "admin"
    )

    assert patterns == []


def test_no_leetspeak_pattern():
    patterns = detect_leetspeak_patterns(
        "GxPkLmQ"
    )

    assert patterns == []


def test_common_password_file():
    passwords = load_common_passwords()

    assert len(passwords) > 0
    assert "password" in passwords
    assert "qwerty" in passwords


def test_common_password_detection():
    assert detect_common_password(
        "password"
    ) is True


def test_common_password_case_insensitive():
    assert detect_common_password(
        "PASSWORD"
    ) is True


def test_non_common_password():
    assert detect_common_password(
        "G7!xP9@kL2#mQ8"
    ) is False


def test_dictionary_base():
    matches = detect_dictionary_base(
        "Princess2026!"
    )

    assert "princess" in matches


def test_dictionary_base_with_leetspeak():
    matches = detect_dictionary_base(
        "M0nkey2026!"
    )

    assert "monkey" in matches


def test_dictionary_base_password():
    matches = detect_dictionary_base(
        "P@ssw0rd2026!"
    )

    assert "password" in matches


def test_no_dictionary_base():
    matches = detect_dictionary_base(
        "G7!xP9@kL2#mQ8"
    )

    assert matches == []


def test_dictionary_false_positive():
    matches = detect_dictionary_base(
        "Mariana#X7"
    )

    assert "maria" not in matches


def test_dictionary_substring_false_positive():
    matches = detect_dictionary_base(
        "PasswordManager2026!"
    )

    assert "password" not in matches


def test_entropy():
    entropy = calculate_entropy(
        "Cyber2026!",
        True,
        True,
        True,
        True
    )

    assert entropy > 0


def test_empty_password_entropy():
    entropy = calculate_entropy(
        "",
        False,
        False,
        False,
        False
    )

    assert entropy == 0


def test_longer_password_has_more_entropy():
    short_entropy = calculate_entropy(
        "Cyber1!",
        True,
        True,
        True,
        True
    )

    long_entropy = calculate_entropy(
        "CyberSecurity2026!",
        True,
        True,
        True,
        True
    )

    assert (
        long_entropy
        > short_entropy
    )


def test_crack_time_returns_string():
    result = estimate_crack_time(60)

    assert isinstance(
        result,
        str
    )


def test_large_crack_time_format():
    result = estimate_crack_time(200)

    assert (
        result
        == "> 1 trillion years"
    )


def test_base_score():
    score = calculate_base_score(
        "G7!xP9@kL2#mQ8",
        True,
        True,
        True,
        True
    )

    assert score == 90


def test_base_score_long_password():
    score = calculate_base_score(
        "G7!xP9@kL2#mQ8&R5",
        True,
        True,
        True,
        True
    )

    assert score == 100


def test_base_score_never_above_100():
    score = calculate_base_score(
        "G7!xP9@kL2#mQ8&R5tZ",
        True,
        True,
        True,
        True
    )

    assert score <= 100


def test_penalties_none():
    penalties = calculate_penalties(
        [],
        False,
        False,
        [],
        []
    )

    assert penalties == 0


def test_pattern_penalty():
    penalties = calculate_penalties(
        ["password"],
        False,
        False,
        [],
        []
    )

    assert penalties == 15


def test_multiple_pattern_penalty_cap():
    penalties = calculate_penalties(
        [
            "password",
            "admin",
            "welcome"
        ],
        False,
        False,
        [],
        []
    )

    assert penalties == 30


def test_repetition_penalty():
    penalties = calculate_penalties(
        [],
        True,
        False,
        [],
        []
    )

    assert penalties == 15


def test_sequence_penalty():
    penalties = calculate_penalties(
        [],
        False,
        True,
        [],
        []
    )

    assert penalties == 15


def test_keyboard_penalty():
    penalties = calculate_penalties(
        [],
        False,
        False,
        ["qwerty"],
        []
    )

    assert penalties == 10


def test_leetspeak_penalty():
    penalties = calculate_penalties(
        [],
        False,
        False,
        [],
        ["password"]
    )

    assert penalties == 15


def test_score_range():
    score = calculate_score(
        "G7!xP9@kL2#mQ8",
        True,
        True,
        True,
        True,
        [],
        False,
        False,
        [],
        []
    )

    assert 0 <= score <= 100


def test_score_never_below_zero():
    score = calculate_score(
        "aaa",
        False,
        True,
        False,
        False,
        [
            "password",
            "admin"
        ],
        True,
        True,
        ["qwerty"],
        ["password"]
    )

    assert score == 0


def test_score_details_without_cap():
    details = calculate_score_details(
        "G7!xP9@kL2#mQ8",
        True,
        True,
        True,
        True,
        [],
        False,
        False,
        [],
        [],
        False,
        []
    )

    assert details[
        "base_score"
    ] == 90

    assert details[
        "penalties"
    ] == 0

    assert details[
        "score_before_caps"
    ] == 90

    assert details[
        "applied_cap"
    ] is None

    assert details[
        "final_score"
    ] == 90


def test_score_details_common_password_cap():
    details = calculate_score_details(
        "Password123!",
        True,
        True,
        True,
        True,
        ["password"],
        False,
        True,
        [],
        [],
        True,
        []
    )

    assert details[
        "applied_cap"
    ] == 20

    assert details[
        "final_score"
    ] <= 20


def test_score_details_dictionary_cap():
    details = calculate_score_details(
        "Princess2026!",
        True,
        True,
        True,
        True,
        [],
        False,
        False,
        [],
        [],
        False,
        ["princess"]
    )

    assert details[
        "applied_cap"
    ] == 50

    assert details[
        "final_score"
    ] <= 50


def test_classification():
    assert (
        classify_password(100)
        == "VERY STRONG"
    )

    assert (
        classify_password(80)
        == "VERY STRONG"
    )

    assert (
        classify_password(70)
        == "STRONG"
    )

    assert (
        classify_password(60)
        == "STRONG"
    )

    assert (
        classify_password(50)
        == "MEDIUM"
    )

    assert (
        classify_password(40)
        == "MEDIUM"
    )

    assert (
        classify_password(20)
        == "WEAK"
    )

    assert (
        classify_password(0)
        == "WEAK"
    )


def test_security_issue_pattern():
    issues = generate_security_issues(
        ["password"],
        False,
        False,
        [],
        [],
        False,
        []
    )

    assert (
        "[-15] Predictable password pattern detected"
        in issues
    )


def test_security_issue_repetition():
    issues = generate_security_issues(
        [],
        True,
        False,
        [],
        [],
        False,
        []
    )

    assert (
        "[-15] Repeated characters detected"
        in issues
    )


def test_security_issue_sequence():
    issues = generate_security_issues(
        [],
        False,
        True,
        [],
        [],
        False,
        []
    )

    assert (
        "[-15] Sequential characters detected"
        in issues
    )


def test_security_issue_keyboard():
    issues = generate_security_issues(
        [],
        False,
        False,
        ["qwerty"],
        [],
        False,
        []
    )

    assert (
        "[-10] Keyboard pattern detected"
        in issues
    )


def test_security_issue_leetspeak():
    issues = generate_security_issues(
        [],
        False,
        False,
        [],
        ["password"],
        False,
        []
    )

    assert (
        "[-15] Predictable leetspeak substitution detected"
        in issues
    )


def test_security_issue_common_password_cap():
    issues = generate_security_issues(
        [],
        False,
        False,
        [],
        [],
        True,
        []
    )

    assert (
        "[CAP 20] Password found in common password list"
        in issues
    )


def test_security_issue_dictionary_cap():
    issues = generate_security_issues(
        [],
        False,
        False,
        [],
        [],
        False,
        ["princess"]
    )

    assert (
        "[CAP 50] Password is based on a common dictionary word"
        in issues
    )


def test_no_security_issues():
    issues = generate_security_issues(
        [],
        False,
        False,
        [],
        [],
        False,
        []
    )

    assert issues == [
        "No major security issues detected"
    ]


def test_recommendations_for_weak_password():
    recommendations = generate_recommendations(
        "password",
        False,
        True,
        False,
        False,
        ["password"],
        False,
        False,
        [],
        [],
        True,
        ["password"]
    )

    assert (
        "Use at least 12 characters"
        in recommendations
    )

    assert (
        "Do not use passwords found in common password lists"
        in recommendations
    )


def test_recommendations_missing_uppercase():
    recommendations = generate_recommendations(
        "randomtext2026!",
        False,
        True,
        True,
        True,
        [],
        False,
        False,
        [],
        [],
        False,
        []
    )

    assert (
        "Add at least one uppercase letter"
        in recommendations
    )


def test_analyze_password_structure():
    result = analyze_password(
        "G7!xP9@kL2#mQ8"
    )

    assert "length" in result
    assert "score" in result
    assert "strength" in result
    assert "entropy" in result
    assert "crack_time" in result
    assert "score_details" in result
    assert "character_types" in result
    assert "character_counts" in result
    assert "security_checks" in result
    assert "security_issues" in result
    assert "recommendations" in result


def test_score_details_structure():
    result = analyze_password(
        "G7!xP9@kL2#mQ8"
    )

    details = result[
        "score_details"
    ]

    assert "base_score" in details
    assert "penalties" in details
    assert "score_before_caps" in details
    assert "applied_cap" in details
    assert "final_score" in details


def test_security_checks_structure():
    result = analyze_password(
        "G7!xP9@kL2#mQ8"
    )

    checks = result[
        "security_checks"
    ]

    assert "weak_patterns" in checks
    assert "keyboard_patterns" in checks
    assert "leetspeak_patterns" in checks
    assert "common_password" in checks
    assert "dictionary_matches" in checks
    assert "repetition" in checks
    assert "sequence" in checks


def test_final_score_matches_score_details():
    result = analyze_password(
        "G7!xP9@kL2#mQ8"
    )

    assert (
        result["score"]
        == result[
            "score_details"
        ]["final_score"]
    )


def test_analyze_password_score_range():
    result = analyze_password(
        "G7!xP9@kL2#mQ8"
    )

    assert (
        0
        <= result["score"]
        <= 100
    )


def test_analyze_weak_password():
    result = analyze_password(
        "password123"
    )

    assert result["score"] <= 20
    assert result["strength"] == "WEAK"

    assert (
        "password"
        in result[
            "security_checks"
        ]["weak_patterns"]
    )

    assert (
        result[
            "security_checks"
        ]["sequence"]
        is True
    )


def test_plain_password_not_double_counted_as_leetspeak():
    result = analyze_password(
        "password"
    )

    assert (
        result[
            "security_checks"
        ]["leetspeak_patterns"]
        == []
    )


def test_qwerty_not_double_counted_as_weak_pattern():
    result = analyze_password(
        "qwerty"
    )

    assert (
        "qwerty"
        in result[
            "security_checks"
        ]["keyboard_patterns"]
    )

    assert (
        "qwerty"
        not in result[
            "security_checks"
        ]["weak_patterns"]
    )


def test_analyze_leetspeak_password():
    result = analyze_password(
        "P@ssw0rd!"
    )

    assert (
        "password"
        in result[
            "security_checks"
        ]["leetspeak_patterns"]
    )


def test_common_password_score_limit():
    result = analyze_password(
        "password"
    )

    assert result["score"] <= 20

    assert (
        result[
            "score_details"
        ]["applied_cap"]
        == 20
    )

    assert (
        result[
            "security_checks"
        ]["common_password"]
        is True
    )


def test_dictionary_password_score_limit():
    result = analyze_password(
        "Princess2026!"
    )

    assert result["score"] <= 50

    assert (
        result[
            "score_details"
        ]["applied_cap"]
        == 50
    )

    assert (
        "princess"
        in result[
            "security_checks"
        ]["dictionary_matches"]
    )


def test_dictionary_leetspeak_score_limit():
    result = analyze_password(
        "M0nkey2026!"
    )

    assert result["score"] <= 50

    assert (
        result[
            "score_details"
        ]["applied_cap"]
        == 50
    )

    assert (
        "monkey"
        in result[
            "security_checks"
        ]["dictionary_matches"]
    )


def test_generated_password_length():
    password = generate_password(
        20
    )

    assert len(password) == 20


def test_generated_password_minimum_length():
    password = generate_password(
        5
    )

    assert len(password) >= 12


def test_generated_password_contains_required_types():
    password = generate_password(
        16
    )

    result = analyze_characters(
        password
    )

    assert result[0] is True
    assert result[1] is True
    assert result[2] is True
    assert result[3] is True


def test_generated_password_security():
    password = generate_password(
        16
    )

    result = analyze_password(
        password
    )

    checks = result[
        "security_checks"
    ]

    assert result["score"] >= 80

    assert (
        checks["weak_patterns"]
        == []
    )

    assert (
        checks["keyboard_patterns"]
        == []
    )

    assert (
        checks["leetspeak_patterns"]
        == []
    )

    assert (
        checks["common_password"]
        is False
    )

    assert (
        checks["dictionary_matches"]
        == []
    )

    assert (
        checks["repetition"]
        is False
    )

    assert (
        checks["sequence"]
        is False
    )

    assert (
        result["score_details"][
            "penalties"
        ]
        == 0
    )

    assert (
        result["score_details"][
            "applied_cap"
        ]
        is None
    )

    assert result[
        "security_issues"
    ] == [
        "No major security issues detected"
    ]
    