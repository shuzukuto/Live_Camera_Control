"""
Mock infrastructure package for E2E tests.
"""
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
    MockGo2rtcServer,
    MockFFmpegSimulator,
    MockSurveillanceEcosystem,
    mock_ecosystem,
)

__all__ = [
    "MockEZVIZPlatform",
    "MockXiaomiPlatform",
    "MockONVIFDevice",
    "MockGo2rtcServer",
    "MockFFmpegSimulator",
    "MockSurveillanceEcosystem",
    "mock_ecosystem",
]
