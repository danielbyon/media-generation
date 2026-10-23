"""Enable ``python3 -m media_generation`` as the local command entry point."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
