<!-- Slide 1 -->

# 🛡️ Workshop

### Applying the OWASP Top 10 to Django & Python

Sydney • 9 July 2025

---

<!-- Slide 2 -->

## Agenda

1. Warm‑up & rules
2. Eleven “Guess‑the‑Bug” rounds
3. Fix‑it walkthroughs in Django
4. Q & A / further resources

---

<!-- Slide 3 (Round 1 guess) -->

### Round 1 – Guess the flaw

```python
@login_required
def order_detail(request, order_id):
    """Display a single order to its owner or staff."""
    user = request.user

    # Feature flag for upcoming loyalty badges
    if settings.FEATURES.get("LOYALTY_BADGES"):
        preload_badges(user)

    order = Order.objects.get(pk=order_id)
    return render(
        request,
        "orders/detail.html",
        {"order": order, "user": user},
    )
```

---

<!-- Slide 4 (Round 1 reveal) -->

## A01 Broken Access Control

*Risk* – attackers can view or change records that aren’t theirs.

**How to fix (Django):** scope queries to the current user (`Order.objects.get(pk=order_id, user=request.user)`), use object‑level permissions, and block IDOR.

---

<!-- Slide 5 (Round 2 guess) -->

### Round 2 – Guess the flaw

```python
import hashlib, random, string

ALPHABET = string.ascii_letters + string.digits


def make_token(email: str) -> str:
    salt = "".join(random.choices(ALPHABET, k=4))  # cosmetic entropy
    return hashlib.md5((email + salt).encode()).hexdigest()
```

---

<!-- Slide 6 (Round 2 reveal) -->

## A02 Cryptographic Failures

Weak hashing exposes secrets. Use `secrets.token_urlsafe()` or Django’s signing framework and modern password hashers.

---

<!-- Slide 7 (Round 3 guess) -->

### Round 3 – Guess the flaw

```python
def user_search(request):
	last_name = request.GET.get("last_name", "")
	users = [
			# Raw SQL to leverage a custom Postgres function for fuzzy matching
			User.objects.raw(
					"SELECT * FROM users WHERE fuzzy_match(last_name, '%s')" % last_name
			)
	]
	# ...
```

---

<!-- Slide 8 (Round 3 reveal) -->

## A03 Injection

Raw SQL with string formatting allows SQL Injection. Use the ORM or bound parameters instead.

---

<!-- Slide 9 (Round 4 guess) -->

### Round 4 – Guess the flaw

```text
# Product‑spec excerpt (marketing):
# “Store the raw HTML supplied by users and render it unescaped
# on the microsite because the content team needs full control.”
```

---

<!-- Slide 10 (Round 4 reveal) -->

## A04 Insecure Design

Design choices bake in XSS risk. Threat‑model early, sanitise rich content (`bleach`), and adopt defence‑in‑depth.

---

<!-- Slide 11 (Round 5 guess) -->

### Round 5 – Guess the flaw

```python
# settings.py (production)
DEBUG = True
ALLOWED_HOSTS = ["*"]
```

---

<!-- Slide 12 (Round 5 reveal) -->

## A05 Security Misconfiguration

Verbose errors and open hosts. Disable `DEBUG`, restrict hosts, and enable Django’s `SECURE_` settings.

---

<!-- Slide 13 (Round 6 guess) -->

### Round 6 – Guess the flaw

```text
requirements.txt
-----------------
Django==1.11.29  # End‑of‑life
```

---

<!-- Slide 14 (Round 6 reveal) -->

## A06 Vulnerable & Outdated Components

Running EOL software drags in CVEs. Pin supported versions, use Dependabot, and run `safety check` in CI.

---

<!-- Slide 15 (Round 7 guess) -->

### Round 7 – Guess the flaw

```python
from django.contrib.auth import authenticate, login


def signin(request):
    if request.method == "POST":
        user = authenticate(...)
        login(request, user)  # no MFA, no rate‑limit
```

---

<!-- Slide 16 (Round 7 reveal) -->

## A07 Identification & Authentication Failures

Lack of MFA/rate‑limit invites brute–force. Add `django‑axes`, enforce strong hashing and session security.

---

<!-- Slide 17 (Round 8 guess) -->

### Round 8 – Guess the flaw

```bash
# CI script snippet
pip install --no-cache-dir --extra-index-url \
    http://fast-pypi-cache.mathspace.co \
    internal-lib
```

---

<!-- Slide 18 (Round 8 reveal) -->

## A08 Software & Data Integrity Failures

Unsigned internal mirrors enable supply‑chain attacks. Use HTTPS, signed packages, and SLSA‑compliant build provenance.

---

<!-- Slide 19 (Round 9 guess) -->

### Round 9 – Guess the flaw

```python
from django.contrib.auth import authenticate, login

class UserNotFound(Exception):
    ...

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        try:
            user = authenticate(
                username=username, password=request.POST.get("password")
            )
            if user is None:
                raise UserNotFound()
            login(request, user)
            return redirect("dashboard")
        except UserNotFound:
            return render(request, "auth/login.html", {"error": "Invalid credentials"})
```

---

<!-- Slide 20 (Round 9 reveal) -->

## A09 Security Logging & Monitoring Failures

Silently swallowing auth errors leaves no audit trail. Log exceptions, alert on spikes, and ship logs to a SIEM.

---

<!-- Slide 21 (Round 10 guess) -->

### Round 10 – Guess the flaw

```python
def fetch_site(request):
    url = request.GET["url"]
    response = requests.get(url, timeout=4)
    return HttpResponse(response.content)
```

---

<!-- Slide 22 (Round 10 reveal) -->

## A10 Server‑Side Request Forgery (SSRF)

Unfiltered URLs let attackers reach internal resources. Restrict outbound hosts or proxy through a vetted service.

---

<!-- Slide 23 (Round 11 guess) -->

### Round 11 – Guess the flaw (XSS in Admin)

```python
from django.contrib import admin

class MessageAdmin(admin.ModelAdmin):
    list_display = ("sender", "timestamp", "short_user_input")

    def short_user_input(self, obj):
        return obj.user_input[:200]

    short_user_input.allow_tags = True
```

---

<!-- Slide 24 (Round 11 reveal) -->

### XSS via `allow_tags`

By rendering raw HTML from user input, this injects scripts into the admin. Strip/escape or use `format_html` instead.

---

<!-- Slide 25 -->

# Wrap‑up

Prioritise high‑impact fixes first, automate scans (`bandit`, `django‑check‑security`), and keep learning with the OWASP Cheat‑Sheet series.
