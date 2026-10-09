<?php

namespace Omnishield\Stopforumspam;

use Omnishield\Config;
use Omnishield\Exception\InvalidConfigException;
use Omnishield\GatewayFactory;
use Omnishield\GatewayInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * StopForumSpam: are this IP address, this e-mail, this name reported for
 * abuse. Looking up needs no key; reporting does.
 *
 *   options:
 *     threshold: 50                        # the confidence (0-100) from which a match counts
 *     send: [ip, email, name]              # what of the visitor is sent - the address leaves the site: say so in the privacy policy
 *     hash_email: true                     # the e-mail as its MD5 (emailhash), not in clear; StopForumSpam then normalises nothing (Gmail's dots, +tags)
 *     expire: ~                            # days: a sighting older than that does not count
 *     tor: neutral                         # neutral: a Tor exit node counts as reported; ignore: never; block: always
 *     wildcards: true                      # false: StopForumSpam's own lists of hostile domains, names and networks left out (nobadall)
 *     api_key: '%env(default::STOPFORUMSPAM_API_KEY)%'   # only to report a spammer
 *     base_uri: https://api.stopforumspam.org/api        # europe.stopforumspam.org, us.stopforumspam.org to stay in a region
 *     report_uri: https://www.stopforumspam.com/add
 *
 * StopForumSpam's terms (https://www.stopforumspam.com/usage, read on
 * 2026-10-07): 100,000 queries a day, non-commercial use - a commercial
 * system may use the data for its own, internal use -, and not as a
 * firewall: ask about the people who submit a form, never about every
 * visitor.
 */
final class StopforumspamGatewayFactory extends GatewayFactory
{
    public function __construct(private readonly ?HttpClientInterface $http = null)
    {
    }

    protected function populate(Config $c): void
    {
        $c->defaults([
            'omnishield.factory_name' => 'stopforumspam',
            'omnishield.factory_title' => 'StopForumSpam',
            'omnishield.required_options' => [],
            'threshold' => 50,
            'send' => ['ip', 'email', 'name'],
            'hash_email' => true,
            'expire' => null,
            'tor' => 'neutral',
            'wildcards' => true,
            'api_key' => null,
            'base_uri' => StopforumspamGateway::BASE_URI,
            'report_uri' => StopforumspamGateway::REPORT_URI,
        ]);
    }

    protected function build(Config $c): GatewayInterface
    {
        $threshold = (float) $c['threshold'];
        if ($threshold < 0 || $threshold > 100) {
            throw new InvalidConfigException(\sprintf('The "stopforumspam" gateway\'s threshold is a confidence, from 0 to 100: %s.', $c['threshold']));
        }
        $send = $c->list('send');
        if ($unknown = array_diff($send, ['ip', 'email', 'name'])) {
            throw new InvalidConfigException(\sprintf('The "stopforumspam" gateway sends ip, email or name, not %s.', implode(', ', $unknown)));
        }
        $tor = (string) $c['tor'];
        if (!\in_array($tor, ['neutral', 'ignore', 'block'], true)) {
            throw new InvalidConfigException(\sprintf('The "stopforumspam" gateway\'s tor is neutral, ignore or block, not "%s".', $tor));
        }

        return new StopforumspamGateway(
            http: $this->http ?? HttpClient::create(),
            threshold: $threshold,
            send: array_values($send),
            hashEmail: $c->bool('hash_email'),
            expire: null !== $c['expire'] && '' !== $c['expire'] ? max(1, (int) $c['expire']) : null,
            tor: $tor,
            wildcards: $c->bool('wildcards'),
            apiKey: $c->string('api_key'),
            baseUri: $c->string('base_uri') ?? StopforumspamGateway::BASE_URI,
            reportUri: $c->string('report_uri') ?? StopforumspamGateway::REPORT_URI,
        );
    }
}
