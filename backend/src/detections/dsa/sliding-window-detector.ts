/**
 * SentinelX Deterministic Sliding-Window Detector
 *
 * Algorithm Design & Complexity:
 * - Data Structure: Map<string, DequeEntry[]>
 *   - Key: Hash of (sourceIp + ":" + targetUser)
 *   - Value: Monotonic FIFO Queue of event timestamps and IDs
 *
 * Time Complexity:
 * - Eviction: Amortized O(1). Each event timestamp enters the queue once and is shifted out once.
 * - Insertion: O(1) push to array/deque.
 * - Lookup: O(1) average Map hash lookup.
 * - Threshold Evaluation: O(1) (array.length check).
 * Total Time Complexity: Amortized O(1) per incoming event.
 *
 * Space Complexity:
 * - O(K * N), where K is the number of active distinct source keys,
 *   and N is the maximum events falling within the active time window (e.g. 60 seconds).
 * - Stale keys with empty queues are periodically pruned to prevent memory leaks.
 */

export interface WindowEvent {
  id: string;
  timestampMs: number;
}

export interface DetectionResult {
  triggered: boolean;
  ruleId: string;
  ruleName: string;
  sourceKey: string;
  eventCount: number;
  timeWindowSeconds: number;
  triggerEventIds: string[];
}

export class SlidingWindowDetector {
  private readonly windows = new Map<string, WindowEvent[]>();
  private readonly processedEventIds = new Set<string>();

  constructor(
    private readonly ruleId: string = 'RULE-BRUTE-FORCE-001',
    private readonly ruleName: string = 'Brute Force Authentication Pattern',
    private readonly threshold: number = 5,
    private readonly windowDurationSeconds: number = 60,
  ) {}

  /**
   * Evaluates an incoming event against the sliding time window.
   *
   * @param eventId Unique identifier for deduplication
   * @param sourceKey Aggregation key (e.g. sourceIp or sourceIp:targetUser)
   * @param eventTimestampMs Timestamp in milliseconds
   */
  public recordAndEvaluate(
    eventId: string,
    sourceKey: string,
    eventTimestampMs: number,
  ): DetectionResult {
    // Duplicate event prevention
    if (this.processedEventIds.has(eventId)) {
      const existingQueue = this.windows.get(sourceKey) || [];
      return {
        triggered: false,
        ruleId: this.ruleId,
        ruleName: this.ruleName,
        sourceKey,
        eventCount: existingQueue.length,
        timeWindowSeconds: this.windowDurationSeconds,
        triggerEventIds: [],
      };
    }
    this.processedEventIds.add(eventId);

    // Bounded set size for deduplication memory safety (retain last 50,000 IDs)
    if (this.processedEventIds.size > 50000) {
      const firstEntry = this.processedEventIds.values().next().value;
      if (firstEntry) this.processedEventIds.delete(firstEntry);
    }

    let queue = this.windows.get(sourceKey);
    if (!queue) {
      queue = [];
      this.windows.set(sourceKey, queue);
    }

    // Insert event
    queue.push({ id: eventId, timestampMs: eventTimestampMs });

    // Evict expired entries: any event older than (eventTimestampMs - windowDurationSeconds * 1000)
    const windowStartMs = eventTimestampMs - this.windowDurationSeconds * 1000;
    while (queue.length > 0 && queue[0].timestampMs < windowStartMs) {
      queue.shift(); // Amortized O(1)
    }

    const triggered = queue.length >= this.threshold;
    const triggerEventIds = triggered ? queue.map((e) => e.id) : [];

    return {
      triggered,
      ruleId: this.ruleId,
      ruleName: this.ruleName,
      sourceKey,
      eventCount: queue.length,
      timeWindowSeconds: this.windowDurationSeconds,
      triggerEventIds,
    };
  }

  /**
   * Resets the window for a specific key upon incident generation or manual clearance.
   */
  public resetKey(sourceKey: string): void {
    this.windows.delete(sourceKey);
  }

  public clear(): void {
    this.windows.clear();
    this.processedEventIds.clear();
  }
}
