import time

import torch


def measure_inference_latency(
    model,
    input_size: tuple[int, int, int, int] = (1, 3, 224, 224),
    device: str = "cpu",
    warmup_runs: int = 10,
    timed_runs: int = 50,
) -> dict[str, float]:
    model = model.to(device)
    model.eval()
    example = torch.randn(*input_size, device=device)

    with torch.inference_mode():
        for _ in range(warmup_runs):
            _ = model(example)

        start_time = time.perf_counter()
        for _ in range(timed_runs):
            _ = model(example)
        end_time = time.perf_counter()

    average_latency = (end_time - start_time) / timed_runs
    throughput = 1.0 / average_latency if average_latency > 0 else 0.0

    return {
        "latency_seconds": average_latency,
        "latency_milliseconds": average_latency * 1000.0,
        "throughput_samples_per_second": throughput,
    }
