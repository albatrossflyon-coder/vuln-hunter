FROM python:3.12-slim

# semgrep/pip-audit come from requirements.txt; gitleaks and trivy are Go
# binaries with no PyPI package, and git is needed for /scan/url clones.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY requirements.txt .
# requirements.txt intentionally pins click/rich past what semgrep's own
# metadata declares (a verified-working CVE-fix override -- see BUILDLOG).
# A single `pip install -r requirements.txt` re-resolves the whole file
# atomically and fails: pip won't accept a constraint semgrep's own
# metadata says it doesn't support, even though it works fine at runtime.
# Install semgrep ALONE first so its real dependency tree (not just
# click/rich) resolves fully and correctly with nothing else present to
# conflict with. Then install everything else (semgrep excluded) --
# click/rich get bumped to the pinned override versions in place; none of
# semgrep's other already-installed dependencies get touched, since pip's
# default upgrade strategy only re-resolves packages a later spec names.
RUN pip install --no-cache-dir "semgrep>=1.90.0" \
    && grep -v '^semgrep' requirements.txt > requirements-rest.txt \
    && pip install --no-cache-dir -r requirements-rest.txt

COPY . .

ENV API_HOST=0.0.0.0
EXPOSE 8001

CMD ["python", "main.py"]
