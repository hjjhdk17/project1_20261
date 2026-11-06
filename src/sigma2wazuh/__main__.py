"""Cho phép ``python -m sigma2wazuh`` ủy quyền sang ``cli.main``."""

from sigma2wazuh.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
