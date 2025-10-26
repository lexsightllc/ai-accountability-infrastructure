# SPDX-License-Identifier: MPL-2.0
"""Main CLI entry point."""
import click


@click.group()  # type: ignore[misc]
def cli() -> None:
    """AI Trust CLI."""


@cli.command()  # type: ignore[misc]
def version() -> None:
    """Show version information."""
    from ai_trust import __version__

    click.echo(f"AI Trust v{__version__}")


if __name__ == "__main__":
    cli()
