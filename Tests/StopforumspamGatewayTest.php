<?php

namespace Omnishield\Stopforumspam\Tests;

use Omnishield\Exception\InvalidConfigException;
use Omnishield\Exception\NotSupportedException;
use Omnishield\Exception\ProviderException;
use Omnishield\Exception\UnreachableException;
use Omnishield\Model\Identity;
use Omnishield\Model\Reputation;
use Omnishield\Stopforumspam\StopforumspamGateway;
use Omnishield\Stopforumspam\StopforumspamGatewayFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Answers recorded from api.stopforumspam.org on 2026-10-07: the values of
 * StopForumSpam's own documentation (lookup-documentation-values.json,
 * lookup-emailhash.json, lookup-blacklisted-email.json for
 * testing@xrumer.ru), a Tor exit node (185.220.101.1, with and without
 * expire=1), an address reported long ago (1.2.3.4), a malformed address.
 * lookup-not-understood.json is the documentation's error.
 */
final class StopforumspamGatewayTest extends TestCase
{
    /** @var list<array{string, string, array<string, string>}> */
    private array $calls = [];

    /** @param list<string|MockResponse> $answers */
    private function gateway(array $answers, array $options = []): StopforumspamGateway
    {
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$answers): MockResponse {
            parse_str((string) $options['body'], $body);
            $this->calls[] = [$method, $url, $body];
            $answer = array_shift($answers) ?? throw new \LogicException('No answer left.');

            return $answer instanceof MockResponse ? $answer : new MockResponse((string) file_get_contents(__DIR__.'/Fixtures/'.$answer.'.json'), ['response_headers' => ['content-type' => 'application/json;charset=utf-8']]);
        });
        $gateway = (new StopforumspamGatewayFactory($http))->create($options);
        self::assertInstanceOf(StopforumspamGateway::class, $gateway);

        return $gateway;
    }

    public function testTheDocumentationsValuesAreUnknownTodayAndTheEmailLeavesHashed(): void
    {
        $reputation = $this->gateway(['lookup-emailhash'])->lookup(new Identity('91.186.18.61', ' G2fsehis5e@mail.ru', null));

        self::assertFalse($reputation->known);
        self::assertSame([0, 0.0, null, []], [$reputation->frequency, $reputation->confidence, $reputation->lastSeen, $reputation->reasons]);
        self::assertSame(['POST', 'https://api.stopforumspam.org/api'], [$this->calls[0][0], $this->calls[0][1]]);
        self::assertSame(['ip' => '91.186.18.61', 'emailhash' => md5('g2fsehis5e@mail.ru'), 'json' => ''], $this->calls[0][2], 'never the e-mail itself, nothing in the address');
        self::assertSame(['frequency' => 0, 'appears' => 0, 'asn' => 29550, 'country' => 'gb'], $reputation->data['ip']);

        $this->gateway(['lookup-documentation-values'], ['hash_email' => false, 'expire' => 90, 'wildcards' => false])->lookup(new Identity('91.186.18.61', 'g2fsehis5e@mail.ru', 'MariFoogwoogy'));
        self::assertSame(['ip' => '91.186.18.61', 'email' => 'g2fsehis5e@mail.ru', 'username' => 'MariFoogwoogy', 'json' => '', 'expire' => '90', 'nobadall' => ''], $this->calls[1][2]);
    }

    public function testAnAddressReportedOftenAndSurelyIsKnown(): void
    {
        $reputation = $this->gateway(['lookup-tor-exit'])->lookup(new Identity('185.220.101.1'));

        self::assertTrue($reputation->known);
        self::assertSame([91, 95.29, '2026-09-30T23:22:50+00:00', [Reputation::IP, Reputation::TOR]], [$reputation->frequency, $reputation->confidence, $reputation->lastSeen?->format(\DATE_ATOM), $reputation->reasons]);
    }

    public function testAStaleOrUnsureSightingDoesNotCount(): void
    {
        $stale = $this->gateway(['lookup-tor-exit-expired'])->lookup(new Identity('185.220.101.1'));
        self::assertFalse($stale->known, 'a confidence of 95.29, and yet it no longer appears');
        self::assertSame(0.0, $stale->confidence);

        $unsure = $this->gateway(['lookup-low-confidence'])->lookup(new Identity('1.2.3.4'));
        self::assertFalse($unsure->known);
        self::assertSame([3, 0.26], [$unsure->frequency, $unsure->confidence]);
        self::assertTrue($this->gateway(['lookup-low-confidence'], ['threshold' => 0])->lookup(new Identity('1.2.3.4'))->known, 'a threshold of the site\'s');
    }

    public function testTorExitNodesAsTheSiteWants(): void
    {
        self::assertFalse($this->gateway(['lookup-tor-exit'], ['tor' => 'ignore'])->lookup(new Identity('185.220.101.1'))->known);
        self::assertTrue($this->gateway(['lookup-tor-exit-expired'], ['tor' => 'block'])->lookup(new Identity('185.220.101.1'))->known);
    }

    public function testABlacklistedEMailInClear(): void
    {
        $reputation = $this->gateway(['lookup-blacklisted-email'], ['hash_email' => false])->lookup(new Identity(email: 'testing@xrumer.ru'));

        self::assertTrue($reputation->known);
        self::assertSame([255, 99.95, [Reputation::EMAIL]], [$reputation->frequency, $reputation->confidence, $reputation->reasons]);
    }

    public function testOnlyWhatTheSiteSendsIsSentAndNothingIsAskedForNothing(): void
    {
        $gateway = $this->gateway(['lookup-tor-exit'], ['send' => 'ip']);

        self::assertFalse($gateway->lookup(new Identity(null, 'a@example.org', 'Camille'))->known);
        self::assertSame([], $this->calls, 'no address: no call');
        $gateway->lookup(new Identity('185.220.101.1', 'a@example.org', 'Camille'));
        self::assertSame(['ip' => '185.220.101.1', 'json' => ''], $this->calls[0][2]);
        self::assertSame(['ip'], $gateway->capabilities()->reads);
    }

    public function testErrors(): void
    {
        $malformed = $this->gateway(['lookup-invalid-ip'])->lookup(new Identity('not-an-ip'));
        self::assertFalse($malformed->known);
        self::assertSame(['error' => 'invalid ip address'], $malformed->data['ip']);

        try {
            $this->gateway(['lookup-not-understood'])->lookup(new Identity('192.0.2.1'));
            self::fail();
        } catch (ProviderException $e) {
            self::assertSame('[stopforumspam] request not understood', $e->getMessage());
        }

        $this->expectException(UnreachableException::class);
        $this->gateway([new MockResponse('', ['http_code' => 503])])->lookup(new Identity('192.0.2.1'));
    }

    public function testAReportNeedsAKeyAndAllThreeParts(): void
    {
        try {
            $this->gateway([])->report(new Identity('192.0.2.1', 'a@example.org', 'spammer'));
            self::fail();
        } catch (NotSupportedException) {
            self::assertFalse($this->gateway([])->capabilities()->reports);
        }
        try {
            $this->gateway([], ['api_key' => 'k'])->report(new Identity('192.0.2.1', null, 'spammer'));
            self::fail();
        } catch (InvalidConfigException) {
        }

        $gateway = $this->gateway([new MockResponse(''), new MockResponse('<p>Invalid API key</p>', ['http_code' => 403])], ['api_key' => 'k3y']);
        $gateway->report(new Identity('192.0.2.1', 'a@example.org', 'spammer'), 'Buy now');
        self::assertSame(['POST', 'https://www.stopforumspam.com/add', ['username' => 'spammer', 'ip_addr' => '192.0.2.1', 'email' => 'a@example.org', 'evidence' => 'Buy now', 'api_key' => 'k3y']], $this->calls[0]);

        $this->expectExceptionMessage('[stopforumspam] The report was refused (HTTP 403): Invalid API key');
        $gateway->report(new Identity('192.0.2.1', 'a@example.org', 'spammer'));
    }

    public function testWhatIsMisconfigured(): void
    {
        foreach ([['threshold' => 120], ['send' => 'ip,phone'], ['tor' => 'maybe']] as $options) {
            try {
                (new StopforumspamGatewayFactory(new MockHttpClient()))->create($options);
                self::fail(json_encode($options));
            } catch (InvalidConfigException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
