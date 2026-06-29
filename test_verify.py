"""
Quick test for cryptographic timestamp verification.
Run from the project folder:

    venv\\Scripts\\python.exe test_verify.py
"""
import json

from app import app, Analysis, verify_crypto_package, signed_data_matches_analysis


def main():
    with app.app_context():
        analyses = Analysis.query.filter(
            Analysis.timestamp_hash.isnot(None),
            Analysis.timestamp_signature.isnot(None),
        ).order_by(Analysis.id.desc()).limit(5).all()

        if not analyses:
            print("No analyses with timestamps found.")
            print("Upload an image first at http://127.0.0.1:5000/")
            return

        print(f"Found {len(analyses)} recent timestamped analysis(es).\n")

        for analysis in analyses:
            stored_crypto = json.loads(analysis.crypto_timestamp)
            hash_valid, signature_valid, _, _ = verify_crypto_package(stored_crypto)
            db_valid = signed_data_matches_analysis(analysis, stored_crypto.get('data', {}))

            print(f"Analysis #{analysis.id} - {analysis.filename}")
            print(f"  Document Hash:     {analysis.timestamp_hash}")
            print(f"  Digital Signature: {analysis.timestamp_signature}")
            print(f"  Hash valid:        {hash_valid}")
            print(f"  Signature valid:   {signature_valid}")
            print(f"  DB matches signed: {db_valid}")
            print()
            print("  Test in browser:")
            print(
                "  http://127.0.0.1:5000/verify-timestamp"
                f"?hash={analysis.timestamp_hash}"
                f"&signature={analysis.timestamp_signature}"
            )
            print()


if __name__ == '__main__':
    main()
