# Utility scripts

Run commands from the repository root:

- `./scripts/run_demo.sh` — start the local review app on port 8000.
- `./scripts/run_tests.sh` — discover and run the suite under `tests/`.
- `python3 -m scripts.evaluate_outputs PREDICTIONS.csv REFERENCE.csv` — compare
  two explicitly supplied output files.
- `python3 -m scripts.review_demo` — print the case 16 review result without
  writing `output.csv`.
- `python3 scripts/package_submission.py` — rebuild `code.zip` without the
  dataset, generated results, caches, nested archives, or secrets.
