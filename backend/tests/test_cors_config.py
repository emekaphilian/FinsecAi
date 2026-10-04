from app.core.config import PRODUCTION_FRONTEND_ORIGIN, Settings


def test_production_frontend_is_allowed_with_environment_override():
    settings = Settings(_env_file=None, cors_origins="https://admin.example")

    assert settings.cors_origin_list == [
        "https://admin.example",
        PRODUCTION_FRONTEND_ORIGIN,
    ]


def test_production_frontend_is_not_duplicated():
    settings = Settings(
        _env_file=None,
        cors_origins=f"{PRODUCTION_FRONTEND_ORIGIN},https://admin.example",
    )

    assert settings.cors_origin_list.count(PRODUCTION_FRONTEND_ORIGIN) == 1
