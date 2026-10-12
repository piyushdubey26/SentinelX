import { Injectable, Logger } from '@nestjs/common';
import { StreamingDriver } from './streaming-driver.interface';
import { StreamMessage, ConsumerLagInfo } from '../streaming.types';

interface PartitionQueue {
  messages: StreamMessage[];
  highWatermark: number;
}

@Injectable()
export class EmbeddedStreamingDriver implements StreamingDriver {
  readonly name = 'embedded' as const;
  private readonly logger = new Logger(EmbeddedStreamingDriver.name);
  private status: 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED' = 'DISCONNECTED';

  // Topic -> Partition ID -> Queue
  private readonly topics = new Map<string, Map<number, PartitionQueue>>();
  private readonly numPartitions = 3;

  // Topic -> GroupId -> Partition ID -> Committed Offset
  private readonly committedOffsets = new Map<string, Map<string, Map<number, number>>>();

  // Subscribers
  private readonly subscribers = new Map<
    string,
    { groupId: string; handler: (message: StreamMessage) => Promise<void> }[]
  >();

  async connect(): Promise<void> {
    this.status = 'CONNECTED';
    this.logger.log('[EmbeddedStreaming] Connected in-memory streaming broker (3 partitions/topic).');
  }

  async disconnect(): Promise<void> {
    this.status = 'DISCONNECTED';
    this.topics.clear();
    this.committedOffsets.clear();
    this.subscribers.clear();
  }

  getStatus(): 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED' {
    return this.status;
  }

  private getPartition(key: string): number {
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      hash = (hash << 5) - hash + key.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash) % this.numPartitions;
  }

  async publish(topic: string, message: StreamMessage): Promise<void> {
    if (!this.topics.has(topic)) {
      const pMap = new Map<number, PartitionQueue>();
      for (let p = 0; p < this.numPartitions; p++) {
        pMap.set(p, { messages: [], highWatermark: 0 });
      }
      this.topics.set(topic, pMap);
    }

    const partition = message.partition !== undefined ? message.partition : this.getPartition(message.key || '');
    const pQueue = this.topics.get(topic)!.get(partition)!;

    const offset = pQueue.highWatermark;
    pQueue.highWatermark++;

    const msgWithMetadata: StreamMessage = {
      ...message,
      topic,
      partition,
      offset,
      timestamp: Date.now(),
    };

    pQueue.messages.push(msgWithMetadata);

    // Deliver to subscribers
    const topicSubscribers = this.subscribers.get(topic) || [];
    for (const sub of topicSubscribers) {
      // Async dispatch without blocking producer
      setImmediate(async () => {
        try {
          await sub.handler(msgWithMetadata);
          this.commitOffset(topic, sub.groupId, partition, offset + 1);
        } catch (err) {
          this.logger.error(`[EmbeddedStreaming] Error delivering message ${offset} to group ${sub.groupId}:`, err);
        }
      });
    }
  }

  async subscribe(
    topic: string,
    groupId: string,
    handler: (message: StreamMessage) => Promise<void>,
  ): Promise<void> {
    if (!this.subscribers.has(topic)) {
      this.subscribers.set(topic, []);
    }
    this.subscribers.get(topic)!.push({ groupId, handler });

    // Initialize committed offsets if not set
    if (!this.committedOffsets.has(topic)) {
      this.committedOffsets.set(topic, new Map());
    }
    if (!this.committedOffsets.get(topic)!.has(groupId)) {
      const pMap = new Map<number, number>();
      for (let p = 0; p < this.numPartitions; p++) {
        pMap.set(p, 0);
      }
      this.committedOffsets.get(topic)!.set(groupId, pMap);
    }
  }

  private commitOffset(topic: string, groupId: string, partition: number, offset: number): void {
    const groupMap = this.committedOffsets.get(topic)?.get(groupId);
    if (groupMap) {
      groupMap.set(partition, offset);
    }
  }

  async getLag(topic: string): Promise<ConsumerLagInfo[]> {
    const pMap = this.topics.get(topic);
    if (!pMap) return [];

    const lagList: ConsumerLagInfo[] = [];
    const groupMap = this.committedOffsets.get(topic);

    for (let p = 0; p < this.numPartitions; p++) {
      const queue = pMap.get(p)!;
      const hw = queue.highWatermark;

      // Find lowest committed offset among active groups
      let minCommitted = hw;
      if (groupMap) {
        for (const offsets of groupMap.values()) {
          const committed = offsets.get(p) ?? 0;
          if (committed < minCommitted) {
            minCommitted = committed;
          }
        }
      }

      lagList.push({
        topic,
        partition: p,
        currentOffset: minCommitted,
        highWatermark: hw,
        lag: Math.max(0, hw - minCommitted),
      });
    }

    return lagList;
  }
}
