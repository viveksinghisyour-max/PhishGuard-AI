import json
import sys
from app.email_engine.ingestion import process_eml_file

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample_emails/test_email.eml"
    try:
        analysis = process_eml_file(target_file)
        print(json.dumps(analysis, indent=2))
    except Exception as err:
        print(f"Error processing email: {err}")