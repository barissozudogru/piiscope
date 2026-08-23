# Contributing to piiscope

Thank you for your interest in contributing to piiscope!

## Development Setup

To set up your local development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/barissozudogru/piiscope.git
   cd piiscope
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install the package in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev,parquet]"
   ```
4. Run pre-flight checks to ensure everything is set up correctly:
   ```bash
   ruff check piiscope tests && pytest -q
   ```

## Adding a Detector

If you want to add a new PII detector, you need to update the relevant pattern files and add a test:
1. Regex patterns live in `piiscope/detection/regex_patterns.py`.
2. Jurisdiction-specific logic lives in `piiscope/detection/jurisdictions/<jurisdiction>.py`.
3. Add a corresponding test in the `tests/` directory to verify your detector works correctly.

## Adding a Jurisdiction

To add a new jurisdiction (e.g., beyond GDPR, CCPA, KVKK, LGPD):
1. Create a new file for the jurisdiction under `piiscope/detection/jurisdictions/`.
2. Implement the required scoring and detection logic for the specific laws.
3. Write unit tests for the jurisdiction in the `tests/` directory.

## Data Privacy Rule

All samples and tests must contain **only synthetic data**. Never commit real personal data, production database dumps, or real files to this repository.

## Commit Message Style

We use [Conventional Commits](https://www.conventionalcommits.org/). Please format your commit messages accordingly (e.g., `feat: add new credit card detector`, `fix: correct scoring logic in GDPR`).

## Pull Request Expectations

When submitting a pull request:
- Provide a clear summary of the changes.
- Explain how you tested the changes.
- Ensure all tests pass and the linter is clean.
- Verify that no real personal data is included.
