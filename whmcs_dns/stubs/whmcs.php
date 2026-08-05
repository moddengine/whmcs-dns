<?php

namespace WHMCS\Database {
    final class Capsule
    {
        public static function schema(): mixed {}
        public static function table(string $table): mixed {}
        public static function connection(): mixed {}
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
}
