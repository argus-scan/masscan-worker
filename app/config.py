from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    nats_url: str = "nats://localhost:4222"
    port: int = 8007
    masscan_rate: int = 1000
    masscan_ports: str = "0-65535"
