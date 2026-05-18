# CommonPHP Security

CommonPHP Security provides security-focused contracts and services for CommonPHP applications. It supports authorization, protection, identity-aware behavior, CSRF handling, and other security concerns that sit around authentication.

The package keeps security behavior explicit and modular while allowing authentication sources, session behavior, and HTTP integrations to remain driver-based or package-specific.

## Requirements

- PHP `^8.5`
- `comphp/runtime:^0.3`

## Installation

Once this package is available through your Composer repositories, install it with:

```bash
composer require comphp/security
```

## Usage

```php
<?php

// TODO: Write usage
```

## Package Notes

This package should focus on authorization, CSRF-style protection, identity-aware checks, and security service contracts. Authentication sources and login behavior may be provided by `comphp/auth` and related drivers.

## Error Handling

Security failures should use package-specific exceptions or explicit result objects so applications can distinguish denied access from runtime failures.

## Documentation

- [Documentation index](docs/index.md)
- [Usage](docs/usage.md)
- [Testing](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

MIT. See [LICENSE.md](LICENSE.md).
