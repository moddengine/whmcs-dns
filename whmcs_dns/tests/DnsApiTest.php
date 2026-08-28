<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class DnsApiTest extends TestCase
{
    #[RunInSeparateProcess]
    public function testDnsApiAndManagementChecks(): void
    {
        $level = ob_get_level();
        ob_start();
        try {
            require __DIR__ . '/dns-api.php';
            $output = ob_get_clean();
        } finally {
            while (ob_get_level() > $level) {
                ob_end_clean();
            }
        }
        self::assertSame("DNS API checks passed.\n", $output);
    }
}
