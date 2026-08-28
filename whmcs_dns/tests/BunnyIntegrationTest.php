<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class BunnyIntegrationTest extends TestCase
{
    #[Group('integration')]
    #[RunInSeparateProcess]
    public function testBunnyIntegration(): void
    {
        if (!is_string(getenv('BUNNY_API_KEY')) || getenv('BUNNY_API_KEY') === '') {
            self::markTestSkipped('BUNNY_API_KEY is not set.');
        }

        $level = ob_get_level();
        ob_start();
        try {
            require __DIR__ . '/integration-bunny.php';
            $output = ob_get_clean();
        } finally {
            while (ob_get_level() > $level) {
                ob_end_clean();
            }
        }
        self::assertSame("Bunny integration checks passed.\n", $output);
    }
}
