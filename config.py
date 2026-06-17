from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration settings"""
    email: str = "ramyayarava76@gmail.com"
    username: str = "ramyayarava76"
    app_name: str = "Firewall Audit Backend"
    app_version: str = "1.0.0"
    debug: bool = False
    cors_origins: list[str] = ["*"]

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


# Create a global settings instance
settings = Settings()
