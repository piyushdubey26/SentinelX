import { StreamMessage, ConsumerLagInfo } from '../streaming.types';

export interface StreamingDriver {
  readonly name: 'kafka' | 'embedded';

  connect(): Promise<void>;
  disconnect(): Promise<void>;

  publish(topic: string, message: StreamMessage): Promise<void>;

  subscribe(
    topic: string,
    groupId: string,
    handler: (message: StreamMessage) => Promise<void>,
  ): Promise<void>;

  getLag(topic: string): Promise<ConsumerLagInfo[]>;
  getStatus(): 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED';
}
