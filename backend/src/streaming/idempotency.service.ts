import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { IdempotencyKey } from './entities/idempotency-key.entity';

@Injectable()
export class IdempotencyService {
  private readonly logger = new Logger(IdempotencyService.name);
  private readonly memoryCache = new Map<string, number>();
  private readonly MAX_MEMORY_KEYS = 50000;

  constructor(
    @InjectRepository(IdempotencyKey)
    private readonly keyRepo: Repository<IdempotencyKey>,
  ) {}

  /**
   * Checks if an idempotency key was already processed.
   * If not, atomically claims it to guarantee exactly-once processing.
   */
  async checkAndClaim(key: string, eventId?: string, ttlHours: number = 24): Promise<boolean> {
    const now = Date.now();

    // 1. Check in-memory cache first for sub-millisecond rejection
    const memoryExpiry = this.memoryCache.get(key);
    if (memoryExpiry && memoryExpiry > now) {
      return false; // Already processed (duplicate)
    }

    // 2. Check Database
    const existing = await this.keyRepo.findOne({ where: { key } });
    if (existing) {
      if (existing.expiresAt.getTime() > now) {
        this.memoryCache.set(key, existing.expiresAt.getTime());
        return false; // Already processed (duplicate)
      }
    }

    // 3. Claim key in Database
    const expiresAt = new Date(now + ttlHours * 60 * 60 * 1000);
    try {
      await this.keyRepo.save({
        key,
        eventId,
        expiresAt,
      });

      // Update in-memory cache with bounded size
      if (this.memoryCache.size >= this.MAX_MEMORY_KEYS) {
        const firstKey = this.memoryCache.keys().next().value;
        if (firstKey) this.memoryCache.delete(firstKey);
      }
      this.memoryCache.set(key, expiresAt.getTime());

      return true; // Successfully claimed (not a duplicate)
    } catch {
      // Primary key conflict under concurrent processing
      return false;
    }
  }

  /**
   * Periodic pruning of expired idempotency keys
   */
  async pruneExpired(): Promise<number> {
    const result = await this.keyRepo.delete({
      expiresAt: LessThan(new Date()),
    });
    return result.affected || 0;
  }
}
