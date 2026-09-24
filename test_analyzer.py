"""
Automated Test Suite for NetTrace
Validates log generation, packet parsing accuracy, and triage workflows.
Run using: pytest test_analyzer.py -v
"""

import os
import pytest

LOG_FILE = 'network_triage.log'

@pytest.fixture(scope="module")
def log_content():
    """Fixture to read system logs for analysis."""
    assert os.path.exists(LOG_FILE), "Critical Failure: Triage log file was not generated."
    with open(LOG_FILE, 'r') as file:
        return file.read()

def test_triage_log_creation():
    """Test Case 1: Verifies the creation of system logs for failure triage."""
    assert os.path.exists(LOG_FILE)
    assert os.path.getsize(LOG_FILE) > 0, "Log file is empty. No traces recorded."

def test_successful_packet_parsing(log_content):
    """Test Case 2: Analyzes logs to ensure networking protocols were captured."""
    # Verifies either Wi-Fi or standard IP packets were successfully dissected
    has_wifi = "802.11 Wi-Fi Frame" in log_content
    has_ip = "IP Traffic" in log_content
    
    assert has_wifi or has_ip, "No valid network protocols found in the parsing logs."

def test_zero_dissection_errors(log_content):
    """Test Case 3: Scans the log output to identify any root-cause parsing failures."""
    # Ensures the Scapy dissector did not throw exceptions during runtime
    assert "Packet Dissection Error" not in log_content, "System error detected during packet dissection."

def test_session_termination(log_content):
    """Test Case 4: Validates proper script execution and memory cleanup."""
    assert "Capture session terminated successfully" in log_content, "Capture session did not exit cleanly."
