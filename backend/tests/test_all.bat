@echo off
setlocal enabledelayedexpansion
cls

set BASE=http://localhost:8000
set API=%BASE%/api/v1
set KEY=your-static-api-key-here

echo ============================================================
echo   MiniSOC ThreatLens - Complete API Test
echo ============================================================
echo.

REM ========== CORE ==========
echo [1/25] GET /
curl -s %BASE%/
echo.
echo.

echo [2/25] GET /health
curl -s %BASE%/health
echo.
echo.

REM ========== EVENTS ==========
echo [3/25] POST /api/v1/events (single)
curl -s -X POST %API%/events ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %KEY%" ^
  -d "{\"timestamp\":\"2026-09-16T16:00:01Z\",\"host\":\"api-test-server\",\"source_ip\":\"10.10.10.250\",\"event_type\":\"ssh_failed_login\",\"username\":\"tester\",\"severity\":\"low\",\"raw_event\":\"API test event\"}"
echo.
echo.

echo [4/25] POST /api/v1/events/batch
curl -s -X POST %API%/events/batch ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: %KEY%" ^
  -d "{\"events\":[{\"timestamp\":\"2026-09-16T16:00:02Z\",\"host\":\"api-test-server\",\"source_ip\":\"10.10.10.250\",\"event_type\":\"ssh_failed_login\",\"username\":\"tester\",\"severity\":\"low\",\"raw_event\":\"Batch 1\"},{\"timestamp\":\"2026-09-16T16:00:03Z\",\"host\":\"api-test-server\",\"source_ip\":\"10.10.10.250\",\"event_type\":\"ssh_failed_login\",\"username\":\"tester\",\"severity\":\"low\",\"raw_event\":\"Batch 2\"}]}"
echo.
echo.

echo [5/25] GET /api/v1/events
curl -s "%API%/events?limit=3"
echo.
echo.

REM ========== ALERTS ==========
echo [6/25] GET /api/v1/alerts
curl -s "%API%/alerts?limit=2"
echo.
echo.

echo [7/25] GET /api/v1/alerts/stats
curl -s %API%/alerts/stats
echo.
echo.

REM ========== INCIDENTS ==========
echo [8/25] GET /api/v1/incidents
curl -s "%API%/incidents?limit=1"
echo.
echo.

echo [9/25] GET /api/v1/incidents/search
curl -s "%API%/incidents/search?q=ssh"
echo.
echo.

REM ========== STATS ==========
echo [10/25] GET /api/v1/stats/overview
curl -s %API%/stats/overview
echo.
echo.

echo [11/25] GET /api/v1/storage/stats
curl -s %API%/storage/stats
echo.
echo.

REM ========== NETWORK ==========
echo [12/25] GET /api/v1/network/stats
curl -s %API%/network/stats
echo.
echo.

echo [13/25] GET /api/v1/network/hosts
curl -s %API%/network/hosts
echo.
echo.

echo [14/25] GET /api/v1/network/connections
curl -s "%API%/network/connections?limit=3"
echo.
echo.

echo [15/25] GET /api/v1/network/timeline
curl -s "%API%/network/timeline?hours=24"
echo.
echo.

echo [16/25] GET /api/v1/network/anomalies
curl -s %API%/network/anomalies
echo.
echo.

REM ========== DETECTIONS ==========
echo [17/25] GET /api/v1/detections/rules
curl -s %API%/detections/rules
echo.
echo.

echo [18/25] GET /api/v1/detections/stats
curl -s %API%/detections/stats
echo.
echo.

echo [19/25] GET /api/v1/detections/rules/AUTH-001
curl -s %API%/detections/rules/AUTH-001
echo.
echo.

REM ========== MITRE ==========
echo [20/25] GET /api/v1/mitre/techniques
curl -s %API%/mitre/techniques
echo.
echo.

echo [21/25] GET /api/v1/mitre/tactics
curl -s %API%/mitre/tactics
echo.
echo.

echo [22/25] GET /api/v1/mitre/techniques/T1110
curl -s %API%/mitre/techniques/T1110
echo.
echo.

REM ========== SIMULATOR ==========
echo [23/25] GET /api/v1/simulate/scenarios
curl -s %API%/simulate/scenarios
echo.
echo.

echo [24/25] POST /api/v1/simulate/ssh-brute-force
curl -s -X POST %API%/simulate/ssh-brute-force
echo.
echo.

echo [25/25] POST /api/v1/simulate/full-attack
curl -s -X POST %API%/simulate/full-attack
echo.
echo.

echo ============================================================
echo   Test Complete
echo ============================================================
pause