"""
Kafka producer module using confluent-kafka library.

Provides a thread-safe Kafka producer for publishing events
to Kafka topics with proper serialization and error handling.
"""

import json
from datetime import date, datetime
from decimal import Decimal
from threading import Lock
from typing import Optional

from confluent_kafka import KafkaException, Producer

from app.core.config import settings
from app.core.events import EventEnvelope
from app.core.logging import get_logger

logger = get_logger(__name__)


def json_serializer(obj):
    """Custom JSON serializer for complex types."""
    if isinstance(obj, (date, datetime)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def delivery_callback(err, msg):
    """Callback for message delivery reports."""
    if err is not None:
        logger.error(f"Message delivery failed: {err}")
    else:
        logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}]")


class KafkaProducer:
    """
    Singleton Kafka producer using confluent-kafka.

    Thread-safe producer that can be used across the application.
    """

    _instance: Optional[Producer] = None
    _lock: Lock = Lock()
    _started: bool = False

    @classmethod
    def get_producer(cls) -> Optional[Producer]:
        """Get or create the Kafka producer instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    config = {
                        "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
                        "client.id": "user-management-service",
                        "acks": "all",
                        "retries": 3,
                        "retry.backoff.ms": 1000,
                        "enable.idempotence": True,
                    }
                    cls._instance = Producer(config)
        return cls._instance

    @classmethod
    async def start(cls):
        """Initialize the Kafka producer."""
        if not settings.KAFKA_ENABLED:
            logger.info("Kafka is disabled, skipping initialization")
            return

        if not cls._started:
            producer = cls.get_producer()
            if producer:
                cls._started = True
                logger.info(
                    f"Kafka producer initialized: {settings.KAFKA_BOOTSTRAP_SERVERS}"
                )

    @classmethod
    async def stop(cls):
        """Flush and close the Kafka producer."""
        if cls._started and cls._instance:
            with cls._lock:
                if cls._instance:
                    # Flush any remaining messages
                    cls._instance.flush(timeout=10)
                    cls._instance = None
                    cls._started = False
                    logger.info("Kafka producer stopped")

    @classmethod
    def flush(cls, timeout: float = 10.0):
        """Flush pending messages."""
        if cls._instance:
            cls._instance.flush(timeout=timeout)

    @classmethod
    def poll(cls, timeout: float = 0):
        """Poll for delivery callbacks."""
        if cls._instance:
            cls._instance.poll(timeout)


async def publish_event(topic: str, event: EventEnvelope) -> bool:
    """
    Publish an event to a Kafka topic.

    Args:
        topic: Kafka topic name
        event: Event envelope to publish

    Returns:
        True if event was queued successfully, False otherwise
    """
    if not settings.KAFKA_ENABLED:
        logger.debug(f"Kafka disabled, skipping event: {event.event_type}")
        return False

    try:
        producer = KafkaProducer.get_producer()
        if not producer:
            logger.error("Kafka producer not initialized")
            return False

        # Serialize the event
        event_dict = event.model_dump()
        message = json.dumps(event_dict, default=json_serializer).encode("utf-8")

        # Produce the message asynchronously
        producer.produce(
            topic=topic,
            value=message,
            key=event.event_id.encode("utf-8"),
            callback=delivery_callback,
        )

        # Poll to trigger delivery callbacks (non-blocking)
        producer.poll(0)

        logger.info(
            f"Published event {event.event_type} to topic {topic} "
            f"(event_id: {event.event_id})"
        )
        return True

    except KafkaException as e:
        logger.error(f"Kafka error publishing event: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error publishing event: {e}")
        return False


async def publish_event_sync(
    topic: str, event: EventEnvelope, timeout: float = 10.0
) -> bool:
    """
    Publish an event and wait for delivery confirmation.

    Args:
        topic: Kafka topic name
        event: Event envelope to publish
        timeout: Timeout in seconds to wait for delivery

    Returns:
        True if event was delivered successfully, False otherwise
    """
    if not settings.KAFKA_ENABLED:
        logger.debug(f"Kafka disabled, skipping event: {event.event_type}")
        return False

    try:
        producer = KafkaProducer.get_producer()
        if not producer:
            logger.error("Kafka producer not initialized")
            return False

        # Serialize the event
        event_dict = event.model_dump()
        message = json.dumps(event_dict, default=json_serializer).encode("utf-8")

        # Track delivery status
        delivery_result = {"delivered": False, "error": None}

        def sync_callback(err, msg):
            if err is not None:
                delivery_result["error"] = err
                logger.error(f"Message delivery failed: {err}")
            else:
                delivery_result["delivered"] = True
                logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}]")

        # Produce the message
        producer.produce(
            topic=topic,
            value=message,
            key=event.event_id.encode("utf-8"),
            callback=sync_callback,
        )

        # Flush and wait for delivery
        producer.flush(timeout=timeout)

        if delivery_result["delivered"]:
            logger.info(
                f"Published event {event.event_type} to topic {topic} "
                f"(event_id: {event.event_id})"
            )
            return True
        else:
            logger.error(f"Failed to deliver event: {delivery_result['error']}")
            return False

    except KafkaException as e:
        logger.error(f"Kafka error publishing event: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error publishing event: {e}")
        return False
