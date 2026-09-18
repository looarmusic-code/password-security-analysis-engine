from getpass import getpass

from analyzer import (
    analyze_password,
    generate_password
)


def display_list(items):
    if items:
        for item in items:
            print(f"  - {item}")
    else:
        print("  None detected")


def display_analysis(result):
    checks = result["security_checks"]
    score_details = result["score_details"]

    print("\n========================================")
    print("   PASSWORD SECURITY ANALYSIS ENGINE")
    print("              SECURITY REPORT")
    print("========================================")

    print("\nPASSWORD OVERVIEW")
    print(f"  Length: {result['length']} characters")
    print(f"  Strength: {result['strength']}")
    print(f"  Final score: {result['score']} / 100")

    print("\nCHARACTER COMPOSITION")
    print(
        f"  Uppercase: "
        f"{result['character_counts']['uppercase']}"
    )
    print(
        f"  Lowercase: "
        f"{result['character_counts']['lowercase']}"
    )
    print(
        f"  Numbers: "
        f"{result['character_counts']['numbers']}"
    )
    print(
        f"  Symbols: "
        f"{result['character_counts']['symbols']}"
    )

    print("\nSECURITY CHECKS")

    print("\n  Weak patterns:")
    display_list(checks["weak_patterns"])

    print("\n  Keyboard patterns:")
    display_list(checks["keyboard_patterns"])

    print("\n  Predictable substitutions:")
    display_list(checks["leetspeak_patterns"])

    print("\n  Dictionary analysis:")
    print(
        f"  Common password: "
        f"{checks['common_password']}"
    )

    if checks["dictionary_matches"]:
        print(
            "  Common word base: "
            + ", ".join(
                checks["dictionary_matches"]
            )
        )
    else:
        print(
            "  Common word base: None detected"
        )

    print("\n  Additional checks:")
    print(
        f"  Repeated characters: "
        f"{checks['repetition']}"
    )
    print(
        f"  Sequential characters: "
        f"{checks['sequence']}"
    )

    print("\nSECURITY ISSUES")

    for issue in result["security_issues"]:
        print(f"  - {issue}")

    print("\nSCORE BREAKDOWN")
    print(
        f"  Base score: "
        f"{score_details['base_score']} / 100"
    )
    print(
        f"  Penalties: "
        f"-{score_details['penalties']}"
    )
    print(
        f"  Score before caps: "
        f"{score_details['score_before_caps']}"
    )

    if score_details["applied_cap"] is not None:
        print(
            f"  Security cap: "
            f"{score_details['applied_cap']}"
        )
    else:
        print("  Security cap: None")

    print(
        f"  Final score: "
        f"{score_details['final_score']} / 100"
    )

    print("\nTHEORETICAL ENTROPY")
    print(
        f"  {result['entropy']:.2f} bits"
    )

    print("\nTHEORETICAL BRUTE-FORCE ESTIMATE")
    print(
        f"  {result['crack_time']}"
    )

    print(
        "\n  This estimate assumes brute-force searching "
        "and does not account for dictionary attacks, "
        "password reuse, leaked credentials or other "
        "real-world attack methods."
    )

    print("\nRECOMMENDATIONS")

    for recommendation in result["recommendations"]:
        print(f"  - {recommendation}")

    print("\n========================================")


def analyze_password_option():
    password = getpass(
        "Enter your password: ",
        echo_char="*"
    )

    if not password:
        print("\nPassword cannot be empty.")
        return

    result = analyze_password(password)

    display_analysis(result)


def generate_password_option():
    try:
        length = int(
            input("Password length: ")
        )

    except ValueError:
        print(
            "\nInvalid length. Using 16 characters."
        )
        length = 16

    if length < 12:
        print(
            "\nMinimum length is 12 characters."
        )
        print(
            "Generating a 12-character password."
        )

    password = generate_password(length)

    print("\nGenerated password:")
    print(password)

    result = analyze_password(password)

    display_analysis(result)


def main():
    while True:
        print(
            "\n========================================"
        )
        print(
            "   PASSWORD SECURITY ANALYSIS ENGINE"
        )
        print(
            "========================================"
        )

        print("\n1 - Analyze a password")
        print("2 - Generate a secure password")
        print("3 - Exit")

        option = input(
            "\nChoose an option: "
        ).strip()

        if option == "1":
            analyze_password_option()

        elif option == "2":
            generate_password_option()

        elif option == "3":
            print(
                "\nExiting Password Security Analysis Engine."
            )
            break

        else:
            print(
                "\nInvalid option. Choose 1, 2 or 3."
            )


if __name__ == "__main__":
    main()
