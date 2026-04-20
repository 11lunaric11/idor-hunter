# Using idor-hunter on PortSwigger: User ID controlled by request parameter

*Second real-world run of idor-hunter. The tool flagged the lab's
vulnerability correctly — via a different, more severe finding than the
lab's official solve path.*

## The lab

PortSwigger Web Security Academy: [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter).

Classic horizontal privilege escalation. `/my-account?id=<username>` loads
the named user's account page. Official solve: log in as wiener, change
`?id=wiener` to `?id=carlos`, read carlos's API key, submit.

## Manual solve

Two minutes. Logged in as wiener, hit `/my-account?id=wiener`, saw my
own API key. Changed the URL to `?id=carlos`, got carlos's API key:
`1rVg1AmM2WkwLOQMeAJKDBgVhlfuVE4S`. Submitted. Lab green.

## Running the tool

Hypothesis going in: idor-hunter's v0.3 threat model assumes two
authenticated users where one owns a resource and the other shouldn't.
This lab has *one* authenticated user controlling the target via a
parameter they fully control. Different shape. Expected the tool to
probe the URLs mechanically but not fire a high-confidence finding
through its analyzer.

Config (one authed user, list of usernames as IDs, include_unauth on):

```yaml
target:
  base_url: "https://<lab>.web-security-academy.net"
auth:
  users:
    - name: wiener
      cookies: {session: "<session cookie>"}
scans:
  - name: "account horizontal privesc"
    endpoint: "/my-account?id={id}"
    ids:
      type: list
      values: ["wiener", "carlos", "administrator", "admin"]
    baseline_user: wiener
    include_unauth: true
options:
  rate_limit: 2
```

Ran:
$ idor-hunter -c lab-scan.yaml -o ./lab-test
probes:    8
findings:  3
critical 3

## What the tool caught (that I didn't notice manually)

All three findings were `unauth_access` on `/my-account?id=<user>`:

| id= | status | length |
|-----|--------|--------|
| wiener | 200 | 3659 |
| carlos | 200 | 3659 |
| administrator | 200 | 3666 |

The `unauth_access` check fires when an unauthenticated request returns
a substantive 200 response while the scan has an authenticated baseline.
It was meant to catch "missing auth middleware" on ostensibly-protected
routes.

Here that's exactly what happened. The `/my-account` endpoint requires
no authentication at all. Curl confirms:
$ curl -s "https://<lab>/my-account?id=carlos" | grep -i "api|key"
<p>Your username is: carlos</p>
<div>Your API Key is: 1rVg1AmM2WkwLOQMeAJKDBgVhlfuVE4S</div>

No cookies, no session, no referer. The lab's "logged in as wiener"
framing is a misdirect — authentication isn't enforced on this route at
all.

## What this means

The lab officially teaches horizontal privilege escalation via parameter
tampering. Reality is worse: the endpoint is completely unauthenticated.
Same data exposure, one severity level higher (critical vs high in most
taxonomies), and the session cookie is entirely cosmetic.

For the submission I used the parameter-tampering route because that's
the lesson PortSwigger is teaching. If this were a real program, the
report would lead with the unauth access and note the IDOR as a
secondary finding in the same endpoint.

## What this reveals about the tool

Three things:

**1. The tool caught the bug.** Check 1 (`unauth_access`) did exactly
what it was designed to do — compare authed vs unauth responses, flag
the endpoint that shouldn't serve data to anonymous clients. The
analyzer's threat model covered this case cleanly.

**2. Query-string placeholders work today via the `{id}` path trick.**
`endpoint: "/my-account?id={id}"` substitutes correctly. v0.4's planned
explicit query-string support will make this cleaner, but it's not a
blocker for usability.

**3. Real insight: the tool didn't need the "original" threat model to
fire.** I went in expecting the analyzer's cross-user check to be the
useful one. What actually fired was the unauth-access check, which I
hadn't thought about in this context. The tool found the bug via a
different mechanism than I predicted — which is a useful signal that
the analyzer's checks are more independently valuable than I'd modeled
them as.

## Follow-up

- v0.4's "Real APIs" release will add explicit query-string placeholders
  and Burp/HAR import. This scan was a good proof-of-concept that the
  target class is within scope.
- The lab itself probably deserves an issue against PortSwigger — the
  room title implies "access control enforced but broken" when actually
  there's no access control at all. Minor; not filing.

## Scan output

- [findings.json](lab-test/findings.json) (redacted session)
- [probes.csv](lab-test/probes.csv) (redacted session)
