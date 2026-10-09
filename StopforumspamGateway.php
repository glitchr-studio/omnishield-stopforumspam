<?php

namespace Omnishield\Stopforumspam;

use Omnishield\Exception\InvalidConfigException;
use Omnishield\Exception\NotSupportedException;
use Omnishield\Exception\ProviderException;
use Omnishield\Http\Answer;
use Omnishield\Model\Capabilities;
use Omnishield\Model\Identity;
use Omnishield\Model\Reputation;
use Omnishield\ReputationInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * StopForumSpam's API (https://www.stopforumspam.com/usage): one POST - so
 * that nothing of the visitor shows in an address a proxy logs - with ip,
 * email or emailhash, username and json; for each part asked, whether it
 * appears, how often (frequency, 255 for StopForumSpam's own blacklists),
 * when last (lastseen, UTC), how surely (confidence, a percentage), and
 * torexit for a Tor exit node.
 *
 * A part counts when it appears and its confidence reaches the threshold:
 * StopForumSpam gives a confidence even for an address that no longer
 * appears (expire), and a reported address seen three times long ago scores
 * under 1.
 */
final class StopforumspamGateway implements ReputationInterface
{
    public const BASE_URI = 'https://api.stopforumspam.org/api';
    public const REPORT_URI = 'https://www.stopforumspam.com/add';

    /** StopForumSpam's names of the parts, and the family's. */
    private const PARTS = ['ip' => Reputation::IP, 'email' => Reputation::EMAIL, 'emailhash' => Reputation::EMAIL, 'username' => Reputation::NAME];

    /** @param list<string> $send */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly float $threshold = 50,
        private readonly array $send = ['ip', 'email', 'name'],
        private readonly bool $hashEmail = true,
        private readonly ?int $expire = null,
        private readonly string $tor = 'neutral',
        private readonly bool $wildcards = true,
        #[\SensitiveParameter] private readonly ?string $apiKey = null,
        private readonly string $baseUri = self::BASE_URI,
        private readonly string $reportUri = self::REPORT_URI,
    ) {
    }

    public function getName(): string
    {
        return 'stopforumspam';
    }

    public function getTitle(): string
    {
        return 'StopForumSpam';
    }

    public function capabilities(): Capabilities
    {
        return new Capabilities(reputation: true, thirdParty: true, cookies: false, reports: null !== $this->apiKey, reads: $this->send);
    }

    public function lookup(Identity $identity): Reputation
    {
        $fields = [];
        if (\in_array('ip', $this->send, true) && null !== $identity->ip && '' !== $identity->ip) {
            $fields['ip'] = $identity->ip;
        }
        if (\in_array('email', $this->send, true) && null !== $identity->email && '' !== trim($identity->email)) {
            $email = strtolower(trim($identity->email));
            $this->hashEmail ? $fields['emailhash'] = md5($email) : $fields['email'] = $email;
        }
        if (\in_array('name', $this->send, true) && null !== $identity->name && '' !== trim($identity->name)) {
            $fields['username'] = trim($identity->name);
        }
        if ([] === $fields) {
            return Reputation::unknown();
        }
        $fields += array_filter(['json' => '', 'expire' => $this->expire, 'nobadall' => $this->wildcards ? null : ''], static fn ($v) => null !== $v);

        $data = Answer::send($this->http, 'stopforumspam', 'POST', $this->baseUri, ['body' => $fields])->json();
        if (1 !== (int) ($data['success'] ?? 0)) {
            throw new ProviderException('stopforumspam', (string) ($data['error'] ?? 'success: 0'));
        }

        $known = false;
        $frequency = 0;
        $confidence = 0.0;
        $lastSeen = null;
        $reasons = [];
        $parts = [];
        foreach (self::PARTS as $name => $part) {
            if (!\is_array($data[$name] ?? null)) {
                continue;
            }
            $answer = $data[$name];
            unset($answer['value']);
            $parts[$part] = $answer;
            if (isset($answer['error'])) {
                continue;
            }
            $tor = 'ip' === $name && 1 === (int) ($answer['torexit'] ?? 0);
            $appears = 1 === (int) ($answer['appears'] ?? 0);
            $sure = (float) ($answer['confidence'] ?? 0);
            $counts = match (true) {
                $tor && 'ignore' === $this->tor => false,
                $tor && 'block' === $this->tor => true,
                default => $appears && $sure >= $this->threshold,
            };
            $seen = isset($answer['lastseen']) ? \DateTimeImmutable::createFromFormat('Y-m-d H:i:s', (string) $answer['lastseen'], new \DateTimeZone('UTC')) ?: null : null;
            $frequency = max($frequency, (int) ($answer['frequency'] ?? 0));
            $confidence = max($confidence, $appears ? $sure : 0.0);
            $lastSeen = null === $lastSeen || ($seen && $seen > $lastSeen) ? $seen : $lastSeen;
            if ($counts) {
                $known = true;
                $reasons[] = $part;
                if ($tor) {
                    $reasons[] = Reputation::TOR;
                }
            }
        }

        return new Reputation($known, $frequency, $confidence, $lastSeen, $reasons, $parts);
    }

    /**
     * Reports a spammer to StopForumSpam: their address, e-mail and name -
     * all three, StopForumSpam takes nothing less - and what they posted, as
     * evidence. Needs an API key of StopForumSpam's.
     */
    public function report(Identity $identity, string $evidence = ''): void
    {
        if (null === $this->apiKey) {
            throw NotSupportedException::operation('stopforumspam', 'report', 'reporting needs an API key (the api_key option)');
        }
        if (\in_array($identity->ip, [null, ''], true) || \in_array($identity->email, [null, ''], true) || \in_array($identity->name, [null, ''], true)) {
            throw new InvalidConfigException('StopForumSpam takes a report with an IP address, an e-mail and a name, all three.');
        }

        $answer = Answer::send($this->http, 'stopforumspam', 'POST', $this->reportUri, ['body' => ['username' => $identity->name, 'ip_addr' => $identity->ip, 'email' => $identity->email, 'evidence' => $evidence, 'api_key' => $this->apiKey]]);
        if (200 !== $answer->status) {
            $reason = preg_match('~<p[^>]*>(.*?)</p>~is', $answer->body, $m) ? trim(strip_tags($m[1])) : mb_substr(trim(strip_tags($answer->body)), 0, 200);

            throw new ProviderException('stopforumspam', \sprintf('The report was refused (HTTP %d): %s', $answer->status, $reason), (string) $answer->status);
        }
    }
}
