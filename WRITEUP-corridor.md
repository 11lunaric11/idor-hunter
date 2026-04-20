# Using idor-hunter on TryHackMe: Corridor

*A real-world run of my IDOR-hunting tool against a hash-guessing
challenge. Got the flag, found a false-positive bug in my own tool,
filed an issue, queued the fix for v0.3.*

## The room

[Corridor](https://tryhackme.com/room/corridor) presents a landing page
with 13 door links. Each door's URL is an MD5 hash. The hint nudges you
toward testing door numbers not on the landing page.

## Manual recon

Clicking door 1 revealed:
http://10.112.145.52/c4ca4238a0b923820dcc509a6f75849b

`c4ca4238a0b923820dcc509a6f75849b == md5("1")`, confirmed with:
```bash
echo -n "1" | md5sum
```

Pattern: door N → `http://<host>/md5(N)`.

## Automating the sweep

Rather than iterating doors with a bash loop, I used my own tool,
`idor-hunter`, partly as a dogfood exercise. Generated a config with
hashes for doors -10 through 50, plus a few sentinel values (100, 666,
1337, 9999).

```yaml
target:
  base_url: "http://10.112.145.52"
scans:
  - name: "corridor doors"
    endpoint: "/{id}"
    ids:
      type: list
      values: ["<md5 of each door number>", ...]
options:
  rate_limit: 5
```

Ran:
```bash
idor-hunter -c corridor-scan.yaml -o ./corridor-results
```

64 probes, all 200s. Found the outlier with:
```bash
awk -F',' 'NR>1 && $6==200 {print $7, $4}' corridor-results/probes.csv | sort -n | tail
```

Every real door returned 632 bytes. One response returned 797 bytes:
797 http://10.112.145.52/cfcd208495d565ef66e7dff9f98764da

That hash is `md5("0")` — door 0, not listed on the landing page.
Opening that URL revealed `flag{2477ef02448ad9156661ac40a6b8862e}`.

## What the tool got wrong

idor-hunter reported 14 `critical` findings of kind `unauth_access`.
All false positives. Here's why:

The scan had no authenticated baseline user — there's no login on
Corridor. The only "identity" was `__unauth__`. Check 1 of the
analyzer fires whenever an unauthenticated request returns a
substantive 200 response, because in the multi-user threat model
that's an auth-middleware bypass.

But when the *entire app* is unauthenticated by design — common in
CTF challenges and public APIs — every 200 trips the check. Real
bug, not a tool limitation to paper over.

## The fix (shipping in v0.3)

Filed as issue #2:
> Check 1 should only fire when the scan context includes at least
> one authenticated identity. If the only identity is `__unauth__`,
> skip `unauth_access` entirely and emit an `info`-level notice that
> the scan had no auth baseline.

## Takeaways

- **The tool solved the mechanical problem** (automating 64 hash
  lookups) but the signal was in the probe CSV, not the findings.
  That's correct behavior for this target class.
- **Using the tool found a real bug in the tool.** Dogfooding works.
- **Corridor isn't an ideal IDOR target** — it's hash-guessing with
  IDOR framing. Next writeup will target a multi-user room where the
  cross-user diff actually has something to compare.
