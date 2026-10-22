"""Enable ``python3 -m media_generation`` as the local command entry point."""

from .cli import main


raise SystemExit(main())
