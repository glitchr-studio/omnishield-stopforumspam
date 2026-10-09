# omnishield/stopforumspam

**StopForumSpam** for [glitchr/omnishield](https://github.com/glitchr-studio/omnishield): are this IP
address, this e-mail, this name reported for abuse. One question to the public database - no key
needed - and an answer the site reads at its own threshold: how often, how surely, how recently,
and which part matched; a Tor exit node said so.

```php
use Omnishield\Model\Identity;
use Omnishield\Stopforumspam\StopforumspamGatewayFactory;

$list = (new StopforumspamGatewayFactory($httpClient))->create(['threshold' => 50]);

$reputation = $list->lookup(new Identity($ip, $email, $name));   // the e-mail leaves hashed (MD5)
$reputation->known;            // true for 185.220.101.1 on 2026-10-07: confidence 95.29, reasons ['ip', 'tor']
```

```yaml
omnishield:
    gateways:
        reported:
            factory: stopforumspam
            options: { threshold: 50, send: [ip, email] }
```

**The visitor's address goes to a third party** at each check: say so in the privacy policy, keep
the gateway off unless the site wants it, and ask about the people who submit a form - never about
every visitor (StopForumSpam's terms forbid using it as a firewall). Free for non-commercial use,
and for a commercial system's internal use; 100,000 queries a day.

Reporting a spammer back takes an API key of StopForumSpam's: `$list->report($identity, $evidence)`.

[Documentation](docs/index.md): the options, the answer and how it is read, the terms, what was
verified - lookups on the documentation's values and a Tor exit node, for real, on 2026-10-07.

License: MIT since 2026-10-09; earlier versions remain published under LGPL-3.0-or-later.

Formerly `omniguard/stopforumspam`, renamed on 2026-10-10 with its family (`glitchr/omnishield`).
