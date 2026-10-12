import { Injectable, Logger } from '@nestjs/common';
import { Kafka, Producer, Consumer, logLevel } from 'kafkajs';
import { StreamingDriver } from './streaming-driver.interface';
import { StreamMessage, ConsumerLagInfo } from '../streaming.types';

@Injectable()
export class KafkaStreamingDriver implements StreamingDriver {
  readonly name = 'kafka' as const;
  private readonly logger = new Logger(KafkaStreamingDriver.name);
  private kafka?: Kafka;
  private producer?: Producer;
  private consumer?: Consumer;
  private status: 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED' = 'DISCONNECTED';

  constructor() {
    const brokers = process.env.KAFKA_BROKERS ? process.env.KAFKA_BROKERS.split(',') : [];
    if (brokers.length > 0) {
      this.kafka = new Kafka({
        clientId: 'sentinelx-soc-backend',
        brokers,
        logLevel: logLevel.NOTHING,
      });
      this.producer = this.kafka.producer();
    }
  }

  async connect(): Promise<void> {
    if (!this.kafka || !this.producer) {
      this.logger.warn('[KafkaDriver] No KAFKA_BROKERS configured; Kafka driver will remain dormant.');
      return;
    }
    try {
      await this.producer.connect();
      this.status = 'CONNECTED';
      this.logger.log('[KafkaDriver] Connected to Kafka brokers successfully.');
    } catch (err: any) {
      this.status = 'DISCONNECTED';
      this.logger.error(`[KafkaDriver] Failed to connect to Kafka brokers: ${err.message}`);
      throw err;
    }
  }

  async disconnect(): Promise<void> {
    this.status = 'DISCONNECTED';
    if (this.producer) await this.producer.disconnect();
    if (this.consumer) await this.consumer.disconnect();
  }

  getStatus(): 'CONNECTED' | 'REBALANCING' | 'DISCONNECTED' {
    return this.status;
  }

  async publish(topic: string, message: StreamMessage): Promise<void> {
    if (!this.producer || this.status !== 'CONNECTED') {
      throw new Error('Kafka producer is not connected');
    }

    await this.producer.send({
      topic,
      messages: [
        {
          key: message.key,
          value: JSON.stringify(message.value),
          headers: message.headers,
        },
      ],
    });
  }

  async subscribe(
    topic: string,
    groupId: string,
    handler: (message: StreamMessage) => Promise<void>,
  ): Promise<void> {
    if (!this.kafka) return;

    this.consumer = this.kafka.consumer({ groupId });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic, fromBeginning: false });

    await this.consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        const streamMsg: StreamMessage = {
          topic,
          partition,
          offset: parseInt(message.offset, 10),
          key: message.key ? message.key.toString() : '',
          value: message.value ? JSON.parse(message.value.toString()) : null,
          timestamp: message.timestamp ? parseInt(message.timestamp, 10) : Date.now(),
        };
        await handler(streamMsg);
      },
    });
  }

  async getLag(topic: string): Promise<ConsumerLagInfo[]> {
    return [
      {
        topic,
        partition: 0,
        currentOffset: 0,
        highWatermark: 0,
        lag: 0,
      },
    ];
  }
}
