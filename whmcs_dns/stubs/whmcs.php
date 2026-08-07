<?php

namespace WHMCS\Database {
    final class Capsule
    {
        public static function schema(): mixed {}
        public static function table(string $table): mixed {}
        public static function connection(): mixed {}
    }
}

namespace WHMCS\Authentication {
    final class CurrentUser
    {
        public function client(): ?\WHMCS\User\Client {}
        public function user(): ?\WHMCS\User\User {}
        public function isMasqueradingAdmin(): bool {}
    }
}

namespace WHMCS\User {
    final class Client
    {
    }

    final class User
    {
        public int $id;
    }
}

namespace WHMCS\Module\Addon {
    final class Setting
    {
        public static function getSettingValueForModule(string $module, string $setting): ?string {}
    }
}

namespace Illuminate\Database\Schema {
    final class Blueprint
    {
        public function bigIncrements(string $column): ColumnDefinition {}
        public function bigInteger(string $column): ColumnDefinition {}
        public function string(string $column, ?int $length = null): ColumnDefinition {}
        public function text(string $column): ColumnDefinition {}
        public function integer(string $column): ColumnDefinition {}
        public function dateTime(string $column): ColumnDefinition {}
    }

    final class ColumnDefinition
    {
        public function index(): self {}
        public function nullable(): self {}
        public function unique(): self {}
        public function unsigned(): self {}
        public function useCurrent(): self {}
        public function useCurrentOnUpdate(): self {}
    }
}

namespace {
    function add_hook(string $name, int $priority, callable $handler): void {}
    function check_token(): void {}
    function logModuleCall(string $module, string $action, mixed $request, mixed $response, mixed $processedData = null): void {}
    /** @return array<string, mixed> */
    function localAPI(string $command, array $values, ?string $adminUsername = null): array {}
}
