import json
from datetime import date, datetime
from decimal import Decimal

from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaError

from app.core.config import settings
from app.core.events import EventEnvelope
from app.core.logging import get_logger

logger = get_logger(__name__)


class KafkaProducer:
    _instance: AIOKafkaProducer | None = None
    _started: bool = False

    @classmethod
    async def get_producer(cls) -> AIOKafkaProducer:
        if cls._instance is None:
            cls._instance = AIOKafkaProducer(
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(
                    v, default=json_serializer
                ).encode("utf-8"),
            )
        return cls._instance

    @classmethod
    async def start(cls):
        if not settings.KAFKA_ENABLED:
            logger.info("Kafka is disabled, skipping initialization")
            return

        if not cls._started:
            producer = await cls.get_producer()
            await producer.start()
            cls._started = True
            logger.info(f"Kafka producer started: {settings.KAFKA_BOOTSTRAP_SERVERS}")

    @classmethod
    async def stop(cls):
        if cls._started and cls._instance:
            await cls._instance.stop()
            cls._started = False
            cls._instance = None
            logger.info("Kafka producer stopped")


def json_serializer(obj):
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


async def publish_event(topic: str, event: EventEnvelope) -> bool:
    if not settings.KAFKA_ENABLED:
        logger.debug(f"Kafka disabled, skipping event: {event.event_type}")
        return False

    try:
        producer = await KafkaProducer.get_producer()
        event_dict = event.model_dump()
        await producer.send_and_wait(topic, value=event_dict)
        logger.info(
            f"Published event {event.event_type} to topic {topic} "
            f"(event_id: {event.event_id})"
        )
        return True
    except KafkaError as e:
        logger.error(f"Failed to publish event to Kafka: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error publishing event: {e}")
        return False
