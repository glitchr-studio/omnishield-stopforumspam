---
title: omnishield/stopforumspam
order: 1
---

# omnishield/stopforumspam

## Installation

```sh
composer require omnishield/stopforumspam
```

PHP 8.2 or later, `glitchr/omnishield` and `symfony/http-client` (give the factory your
application's client, a `MockHttpClient` in a test). No key to look up; one to report.

## The sources

Written from StopForumSpam's [API usage](https://www.stopforumspam.com/usage) page as it read on
2026-10-07 - the parameters (`ip`, `email`, `emailhash`, `username`, `json`, `expire`, `nobadall`,
`notorexit`, `badtorexit`), the JSON answer, the confidence, the regional servers, the submission
form (`/add`) and the terms - and from its answers that day.

## Options

| Option | Default | |
|---|---|---|
| `threshold` | 50 | the confidence (0-100) from which a part that appears counts |
| `send` | `[ip, email, name]` | what of the visitor is sent; a list or `ip,email` |
| `hash_email` | `true` | the e-mail as its MD5 (`emailhash`), lower-cased and trimmed first; StopForumSpam then normalises nothing (Gmail's dots and `+tags`): `false` sends it in clear and catches more |
| `expire` | | days: a sighting older than that does not count (`expire`) |
| `tor` | `neutral` | a Tor exit node: `neutral` as listed, `ignore` never counts, `block` always counts - decided here, not by `notorexit`/`badtorexit` |
| `wildcards` | `true` | `false` leaves out StopForumSpam's own lists of hostile domains, names and networks (`nobadall`) |
| `api_key` | | only to report |
| `base_uri` | `https://api.stopforumspam.org/api` | `https://europe.stopforumspam.org/api` or `https://us.stopforumspam.org/api` to stay in a region |
| `report_uri` | `https://www.stopforumspam.com/add` | |

## The lookup

One `POST` - so that nothing of the visitor shows in an address a proxy logs - with the parts to
send and `json`. For each part StopForumSpam answers `appears`, `frequency` (255 for its own
blacklists), `lastseen` (UTC), `confidence` (a percentage) and, for an address, `torexit`, `asn`,
`country`.

| `Reputation` | |
|---|---|
| `known` | a part **appears** and its **confidence reaches the threshold** - or a Tor exit node, with `tor: block` |
| `frequency` | the highest of the parts |
| `confidence` | the highest of the parts that appear |
| `lastSeen` | the latest sighting |
| `reasons` | the parts that count: `ip`, `email`, `name`, and `tor` beside `ip` for a Tor exit node |
| `data` | StopForumSpam's answer, part by part (`ip`, `email`, `name`) |

Why both conditions: StopForumSpam gives a confidence even when a part no longer appears (seen
with `expire=1`: `appears: 0`, `confidence: 95.29`), and an address reported three times months
ago appears with a confidence under 1 (1.2.3.4 on 2026-10-07: 0.26).

A part StopForumSpam cannot read (`{"error": "invalid ip address"}`) is left out, its error in
`data`. `{"success": 0, "error": ...}` is a `ProviderException`; no answer, HTTP 5xx or 429 (the
rate exceeded) an `UnreachableException`.

## Reporting

```php
$list->report(new Identity($ip, $email, $name), evidence: $whatTheyPosted);
```

`POST https://www.stopforumspam.com/add` with `username`, `ip_addr`, `email`, `evidence`,
`api_key` - all three parts required, StopForumSpam takes nothing less. HTTP 200 is a report
taken; 403 a refusal, its reason in a paragraph: `ProviderException`. Without `api_key`:
`NotSupportedException`, and `capabilities()->reports` is false.

## The terms

From the usage page, 2026-10-07: "Your use of this data and supporting software is
non-commercial"; "The data here can be accessed by any commerical system provided that it is used
for internal use only"; "API queries are limited to 100,000 per day"; "This API is NOT to be used
as a general software firewall. Checking every incoming connection against the API will be treated
as a denial of service attack". Data offered as is, without guarantee.

## Verified, and not

| | |
|---|---|
| Lookups without a key | **done on 2026-10-07**, against `api.stopforumspam.org` (`bare --live` and the recorded answers): the documentation's address, e-mail, hashed e-mail and name (none appears today), a Tor exit node (185.220.101.1: appears, frequency 91, confidence 95.29, `torexit`), its sighting past `expire=1`, an address reported long ago (1.2.3.4), a blacklisted e-mail (testing@xrumer.ru: 255, 99.95), a malformed address; `europe.stopforumspam.org` answers the same |
| `notorexit` | **seen not to work as documented** on 2026-10-07: the Tor exit node kept `appears: 1` - hence the `tor` option, decided here |
| Reporting (`/add`) | **not verified in real: no API key.** Its request follows the documentation; its answers (200 empty, 403 with a paragraph) too |
| The 100,000-a-day limit and its 503 | not reached |
