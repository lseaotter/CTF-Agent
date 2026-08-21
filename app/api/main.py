"""Compatibility entry point for the maintained local research console."""

from web_interface import app, main

__all__ = ["app", "main"]


if __name__ == "__main__":
    main()
