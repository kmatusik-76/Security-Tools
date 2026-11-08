import sys
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

def load_eml(path):
    with Path(path).open("rb") as file:
        return BytesParser(policy=policy.default).parse(file)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Użycie: python -m analyzer.loader <plik.eml>")
        sys.exit(1)
    msg = load_eml(sys.argv[1])
    print(f"From:    {msg['From']}")
    print(f"Subject: {msg['Subject']}")