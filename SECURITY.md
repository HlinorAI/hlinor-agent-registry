# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

We take the security of Hlinor Agent Registry seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **team@hlinor.ai**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## Scope and Limitations

Hlinor Agent Registry (v0.3.x) is currently a **Reference Implementation** and **Declarative Catalog** for AI agent governance.

- It provides governance contracts and basic runtime validation.
- It is designed to work alongside existing agent frameworks (LangChain, CrewAI, custom runtimes), not replace them.
- Advanced features like immutable audit receipts, signed policy bundles, and resource-level authorization are actively in development for v0.4.

## Security Best Practices

1. Always use `enforcement_mode: strict` in production configurations.
2. Never load registry files from untrusted directories (e.g., `examples/`).
3. Use a `manifest.yaml` to explicitly declare which files should be loaded.
4. Review agent configurations in pull requests before deployment.