import { SlidingWindowDetector } from './sliding-window-detector';

describe('SlidingWindowDetector (Deterministic DSA Algorithm)', () => {
  let detector: SlidingWindowDetector;

  beforeEach(() => {
    // 5 attempts within 60 seconds
    detector = new SlidingWindowDetector('RULE-BRUTE-FORCE-001', 'Brute Force Detection', 5, 60);
  });

  it('1. should NOT trigger when event count is below threshold', () => {
    const baseTime = Date.now();
    for (let i = 1; i <= 4; i++) {
      const result = detector.recordAndEvaluate(`evt-${i}`, '192.168.1.50:admin', baseTime + i * 1000);
      expect(result.triggered).toBe(false);
      expect(result.eventCount).toBe(i);
    }
  });

  it('2. should TRIGGER when reaching exact threshold (5 events within window)', () => {
    const baseTime = Date.now();
    for (let i = 1; i <= 4; i++) {
      detector.recordAndEvaluate(`evt-${i}`, '192.168.1.50:admin', baseTime + i * 1000);
    }

    // 5th event
    const fifth = detector.recordAndEvaluate('evt-5', '192.168.1.50:admin', baseTime + 5000);
    expect(fifth.triggered).toBe(true);
    expect(fifth.eventCount).toBe(5);
    expect(fifth.triggerEventIds).toHaveLength(5);
  });

  it('3. should NOT count duplicate event IDs', () => {
    const baseTime = Date.now();
    detector.recordAndEvaluate('evt-dup-1', '192.168.1.50:admin', baseTime);
    const dupResult = detector.recordAndEvaluate('evt-dup-1', '192.168.1.50:admin', baseTime + 500);

    expect(dupResult.triggered).toBe(false);
    expect(dupResult.eventCount).toBe(1);
  });

  it('4. should EVICT expired events outside sliding window', () => {
    const baseTime = Date.now();
    // 4 events at t = 0, 10s, 20s, 30s
    for (let i = 1; i <= 4; i++) {
      detector.recordAndEvaluate(`evt-${i}`, '192.168.1.50:admin', baseTime + i * 10000);
    }

    // Event 5 arrives at t = 75s (t = 0s and t = 10s have expired because 75s - 60s = 15s)
    const result = detector.recordAndEvaluate('evt-5', '192.168.1.50:admin', baseTime + 85000);
    // Events remaining in window: evt-3 (30s), evt-4 (40s), evt-5 (75s) -> 3 events
    expect(result.triggered).toBe(false);
    expect(result.eventCount).toBe(3);
  });

  it('5. should isolate different source keys independently', () => {
    const baseTime = Date.now();
    // 4 events for IP A
    for (let i = 1; i <= 4; i++) {
      detector.recordAndEvaluate(`evt-a-${i}`, '10.0.0.1:root', baseTime + i * 1000);
    }
    // 1 event for IP B
    const resultB = detector.recordAndEvaluate('evt-b-1', '10.0.0.2:root', baseTime + 5000);
    expect(resultB.triggered).toBe(false);
    expect(resultB.eventCount).toBe(1);
  });
});
