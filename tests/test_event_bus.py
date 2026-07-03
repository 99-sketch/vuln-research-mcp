"""Tests for EventBus — Pub/Sub message backbone."""

import pytest
from src.bus.event_bus import EventBus, Event, EventPriority, get_event_bus


class TestEvent:
    def test_create_event_defaults(self):
        e = Event("test.event", {"key": "value"})
        assert e.event_type == "test.event"
        assert e.data == {"key": "value"}
        assert e.source == ""
        assert e.priority == EventPriority.NORMAL

    def test_create_event_with_all_fields(self):
        e = Event("scan.started", {"port": 80}, "scanner",
                  priority=EventPriority.HIGH, correlation_id="corr-1")
        assert e.event_type == "scan.started"
        assert e.data["port"] == 80
        assert e.source == "scanner"
        assert e.priority == EventPriority.HIGH
        assert e.correlation_id == "corr-1"


class TestEventBusSubscribePublish:
    def test_subscribe_and_publish_sync(self):
        bus = EventBus()
        received = []

        bus.subscribe("scan.completed", lambda e: received.append(e))
        bus.publish(Event("scan.completed", {"target": "example.com"}))

        assert len(received) == 1
        assert received[0].data["target"] == "example.com"

    def test_subscribe_multiple_handlers(self):
        bus = EventBus()
        results = []

        bus.subscribe("vuln.found", lambda e: results.append(1))
        bus.subscribe("vuln.found", lambda e: results.append(2))
        bus.publish(Event("vuln.found"))

        assert results == [1, 2]

    def test_subscribe_different_events(self):
        bus = EventBus()
        a, b = [], []

        bus.subscribe("event.a", lambda e: a.append(e))
        bus.subscribe("event.b", lambda e: b.append(e))

        bus.publish(Event("event.a"))
        bus.publish(Event("event.b"))

        assert len(a) == 1 and len(b) == 1

    def test_subscribe_all_wildcard(self):
        bus = EventBus()
        all_events = []

        bus.subscribe_all(lambda e: all_events.append(e))
        bus.publish(Event("test.a"))
        bus.publish(Event("test.b"))
        bus.publish(Event("other.c"))

        assert len(all_events) == 3

    def test_unsubscribe(self):
        bus = EventBus()
        results = []

        def handler(e):
            results.append(e)

        bus.subscribe("test.unsub", handler)
        bus.publish(Event("test.unsub"))
        assert len(results) == 1

        bus.unsubscribe("test.unsub", handler)
        bus.publish(Event("test.unsub"))
        assert len(results) == 1  # no change after unsubscribe

    def test_unsubscribe_nonexistent(self):
        bus = EventBus()
        results = []

        def handler(e):
            results.append(e)

        # shouldn't raise
        bus.unsubscribe("nonexistent", handler)
        assert len(results) == 0


class TestEventBusHistory:
    def test_history_records_events(self):
        bus = EventBus()
        bus.clear_history()

        bus.publish(Event("event.1"))
        bus.publish(Event("event.2"))
        bus.publish(Event("event.3"))

        history = bus.get_history()
        assert len(history) == 3

    def test_history_filter_by_type(self):
        bus = EventBus()
        bus.clear_history()

        bus.publish(Event("type.a"))
        bus.publish(Event("type.b"))
        bus.publish(Event("type.a"))

        assert len(bus.get_history("type.a")) == 2
        assert len(bus.get_history("type.b")) == 1
        assert len(bus.get_history("type.c")) == 0

    def test_history_limit(self):
        bus = EventBus()
        bus.clear_history()

        for i in range(10):
            bus.publish(Event(f"event.{i}"))

        assert len(bus.get_history(limit=5)) == 5

    def test_clear_history(self):
        bus = EventBus()
        bus.publish(Event("test.event"))
        assert len(bus.get_history()) >= 1

        bus.clear_history()
        assert len(bus.get_history()) == 0

    def test_history_max_size_trims_old_events(self):
        bus = EventBus()
        bus._max_history = 10
        bus.clear_history()

        for i in range(20):
            bus.publish(Event(f"event.{i}"))

        history = bus.get_history()
        assert len(history) <= 15  # trimmed to half + new events


class TestEventBusAsync:
    @pytest.mark.asyncio
    async def test_publish_async_awaits_handlers(self):
        bus = EventBus()
        results = []

        async def handler(event):
            results.append(event.data["id"])

        bus.subscribe_async("async.event", handler)
        await bus.publish_async(Event("async.event", {"id": 42}))

        assert results == [42]

    @pytest.mark.asyncio
    async def test_subscribe_all_async(self):
        bus = EventBus()
        results = []

        async def handler(event):
            results.append(event.event_type)

        bus.subscribe_all_async(handler)
        await bus.publish_async(Event("any.event.1"))
        await bus.publish_async(Event("any.event.2"))

        assert results == ["any.event.1", "any.event.2"]

    @pytest.mark.asyncio
    async def test_async_handler_error_does_not_crash(self):
        bus = EventBus()

        async def bad_handler(event):
            raise RuntimeError("handler bug")

        bus.subscribe_async("bad.event", bad_handler)
        # Should not raise
        await bus.publish_async(Event("bad.event"))


class TestEventBusProperties:
    def test_subscriber_count(self):
        bus = EventBus()
        assert bus.subscriber_count == 0

        bus.subscribe("e1", lambda e: None)
        assert bus.subscriber_count == 1

        bus.subscribe("e1", lambda e: None)
        assert bus.subscriber_count == 2

        bus.subscribe_all(lambda e: None)
        assert bus.subscriber_count == 3

    def test_event_count_increments(self):
        bus = EventBus()
        initial = bus.event_count

        bus.publish(Event("e1"))
        bus.publish(Event("e2"))
        assert bus.event_count == initial + 2


class TestEventBusGlobal:
    def test_get_event_bus_singleton(self):
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

        # Verify it works
        received = []
        bus1.subscribe("global.test", lambda e: received.append(e))
        bus2.publish(Event("global.test", {"val": 1}))
        assert len(received) == 1
        assert received[0].data["val"] == 1
