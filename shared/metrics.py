from shared.config import get_metrics_port

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest, start_http_server
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain"

    class _DummyMetric:
        def labels(self, **kwargs):
            return self

        def inc(self, amount=1):
            return None

        def time(self):
            class _Timer:
                def __enter__(self_inner):
                    return None

                def __exit__(self_inner, exc_type, exc, tb):
                    return False

            return _Timer()

    def Counter(*args, **kwargs):
        return _DummyMetric()

    def Histogram(*args, **kwargs):
        return _DummyMetric()

    def generate_latest():
        return b""

    def start_http_server(*args, **kwargs):
        return None


events_processed_total = Counter(
    "events_processed_total",
    "Total processed events",
    ["service", "stage"],
)

detections_total = Counter(
    "detections_total",
    "Total detections produced",
    ["service", "rule"],
)

alerts_generated_total = Counter(
    "alerts_generated_total",
    "Total alerts generated",
    ["service", "severity"],
)

service_latency = Histogram(
    "service_latency_seconds",
    "Service processing latency",
    ["service", "operation"],
)


def metrics_response():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


def start_metrics_server(service_name: str):
    start_http_server(get_metrics_port(service_name))
