import pytest


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        '--ida_path',
        action='store',
        default='ida64.exe',
        help='Path to Ida executable',
    )


def pytest_configure(config: pytest.Config):
    ida_path = config.getoption('--ida_path')
    # TODO: make tests :)

    print(f'[+] Using {ida_path=} (use --ida_path to configure)')