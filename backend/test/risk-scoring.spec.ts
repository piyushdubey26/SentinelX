import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { RiskScoringService } from '../src/risk/risk-scoring.service';
import { RiskPriorityQueue } from '../src/risk/dsa/priority-queue';
import { Incident, IncidentStatus } from '../src/incidents/entities/incident.entity';
import { Asset, AssetCriticality, AssetEnvironment } from '../src/assets/entities/asset.entity';
import { CandidateIncident } from '../src/correlation/entities/candidate-incident.entity';
import { AuditService } from '../src/audit/audit.service';
import { EventSeverity } from '../src/events/entities/security-event.entity';
import { RiskTier } from '../src/risk/risk.types';

describe('Milestone 2.4 - RiskScoringService & PriorityQueue DSA', () => {
  let service: RiskScoringService;

  const mockIncidentRepo = {
    findOne: jest.fn(),
    find: jest.fn(),
    save: jest.fn(),
    createQueryBuilder: jest.fn(),
  };

  const mockAssetRepo = {
    findOne: jest.fn(),
  };

  const mockCandidateRepo = {
    findOne: jest.fn(),
  };

  const mockAuditService = {
    logAction: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RiskScoringService,
        {
          provide: getRepositoryToken(Incident),
          useValue: mockIncidentRepo,
        },
        {
          provide: getRepositoryToken(Asset),
          useValue: mockAssetRepo,
        },
        {
          provide: getRepositoryToken(CandidateIncident),
          useValue: mockCandidateRepo,
        },
        {
          provide: AuditService,
          useValue: mockAuditService,
        },
      ],
    }).compile();

    service = module.get<RiskScoringService>(RiskScoringService);
    jest.clearAllMocks();
  });

  describe('1. Binary Heap Priority Queue (RiskPriorityQueue)', () => {
    it('maintains Max-Heap invariant (highest priority extracted first)', () => {
      const pq = new RiskPriorityQueue<string>('MAX');
      pq.insert('low', 10);
      pq.insert('critical', 95);
      pq.insert('high', 75);
      pq.insert('medium', 50);

      expect(pq.size()).toBe(4);
      expect(pq.peek()).toBe('critical');
      expect(pq.peekPriority()).toBe(95);

      expect(pq.extract()).toBe('critical');
      expect(pq.extract()).toBe('high');
      expect(pq.extract()).toBe('medium');
      expect(pq.extract()).toBe('low');
      expect(pq.isEmpty()).toBe(true);
      expect(pq.extract()).toBeUndefined();
    });

    it('enforces deterministic FIFO tie-breaking on identical priorities', () => {
      const pq = new RiskPriorityQueue<string>('MAX');
      pq.insert('first_incident', 80);
      pq.insert('second_incident', 80);
      pq.insert('third_incident', 80);

      expect(pq.extract()).toBe('first_incident');
      expect(pq.extract()).toBe('second_incident');
      expect(pq.extract()).toBe('third_incident');
    });

    it('handles empty queue edge cases cleanly', () => {
      const pq = new RiskPriorityQueue<string>();
      expect(pq.size()).toBe(0);
      expect(pq.isEmpty()).toBe(true);
      expect(pq.peek()).toBeUndefined();
      expect(pq.peekPriority()).toBeUndefined();
      expect(pq.extract()).toBeUndefined();
      expect(pq.drainSorted()).toEqual([]);
    });

    it('selects Top-K items in O(N log K) time with equivalent outcome to full sorting', () => {
      const items = [
        { item: 'INC-1', priority: 45.2 },
        { item: 'INC-2', priority: 88.5 },
        { item: 'INC-3', priority: 12.0 },
        { item: 'INC-4', priority: 99.1 },
        { item: 'INC-5', priority: 72.4 },
        { item: 'INC-6', priority: 61.8 },
        { item: 'INC-7', priority: 95.0 },
      ];

      const top3 = RiskPriorityQueue.topK(items, 3);
      expect(top3).toEqual(['INC-4', 'INC-7', 'INC-2']);

      // Edge cases
      expect(RiskPriorityQueue.topK([], 5)).toEqual([]);
      expect(RiskPriorityQueue.topK(items, 0)).toEqual([]);
      expect(RiskPriorityQueue.topK(items, 20).length).toBe(7);
      expect(RiskPriorityQueue.topK(items, 20)[0]).toBe('INC-4');
    });
  });

  describe('2. Mathematical Risk Scoring Formula & Boundaries', () => {
    it('evaluates maximum risk score bounded by 100 for a critical incident on critical production asset', () => {
      const now = new Date();
      const breakdown = service.evaluateRisk(
        {
          incidentId: 'inc-test-crit',
          severity: EventSeverity.CRITICAL,
          assetCriticality: AssetCriticality.CRITICAL,
          assetEnvironment: AssetEnvironment.PRODUCTION,
          correlationConfidence: 1.0,
          eventCount: 50, // Reaches saturation
          detectionRuleSeverity: EventSeverity.CRITICAL,
          blastRadiusCriticalAssets: 3,
          blastRadiusTotalNodes: 10,
          lastSeen: now,
        },
        now,
      );

      expect(breakdown.score).toBeGreaterThanOrEqual(95.0);
      expect(breakdown.score).toBeLessThanOrEqual(100.0);
      expect(breakdown.tier).toBe(RiskTier.CRITICAL);
      expect(breakdown.components.impact.severityScore).toBe(1.0);
      expect(breakdown.components.impact.assetCriticalityScore).toBe(1.0);
      expect(breakdown.components.impact.environmentModifier).toBe(1.0);
      expect(breakdown.components.confidence.velocityScore).toBe(1.0);
      expect(breakdown.components.recency.decayMultiplier).toBe(1.0);
    });

    it('evaluates lowest risk tier for an informational event on low criticality dev asset', () => {
      const now = new Date();
      const breakdown = service.evaluateRisk(
        {
          incidentId: 'inc-test-low',
          severity: EventSeverity.INFO,
          assetCriticality: AssetCriticality.LOW,
          assetEnvironment: AssetEnvironment.DEVELOPMENT,
          correlationConfidence: 0.1,
          eventCount: 1,
          detectionRuleSeverity: EventSeverity.LOW,
          blastRadiusCriticalAssets: 0,
          blastRadiusTotalNodes: 1,
          lastSeen: now,
        },
        now,
      );

      expect(breakdown.score).toBeLessThan(35.0);
      expect(breakdown.tier).toBe(RiskTier.LOW);
    });

    it('keeps Severity (Impact) and Confidence conceptually distinct', () => {
      const now = new Date();

      // High Impact (Critical severity & asset), but Low Confidence (Uncorroborated single alert)
      const highImpactLowConf = service.evaluateRisk(
        {
          incidentId: 'inc-high-imp',
          severity: EventSeverity.CRITICAL,
          assetCriticality: AssetCriticality.CRITICAL,
          assetEnvironment: AssetEnvironment.PRODUCTION,
          correlationConfidence: 0.20,
          eventCount: 1,
          lastSeen: now,
        },
        now,
      );

      // Low Impact (Medium severity, Low asset), but High Confidence (Multi-event corroborated)
      const lowImpactHighConf = service.evaluateRisk(
        {
          incidentId: 'inc-low-imp',
          severity: EventSeverity.MEDIUM,
          assetCriticality: AssetCriticality.LOW,
          assetEnvironment: AssetEnvironment.DEVELOPMENT,
          correlationConfidence: 0.95,
          eventCount: 50,
          lastSeen: now,
        },
        now,
      );

      expect(highImpactLowConf.components.impact.score).toBeGreaterThan(
        lowImpactHighConf.components.impact.score,
      );
      expect(highImpactLowConf.components.confidence.score).toBeLessThan(
        lowImpactHighConf.components.confidence.score,
      );
    });
  });

  describe('3. Sublinear Event Flood Dampening (Anti-Flooding Check)', () => {
    it('applies diminishing logarithmic returns and prevents 10,000 events from inflating score to infinity', () => {
      const now = new Date();

      const singleEvent = service.evaluateRisk(
        {
          incidentId: 'inc-flood-1',
          severity: EventSeverity.HIGH,
          eventCount: 1,
          lastSeen: now,
        },
        now,
      );

      const fiftyEvents = service.evaluateRisk(
        {
          incidentId: 'inc-flood-50',
          severity: EventSeverity.HIGH,
          eventCount: 50, // Config saturation point
          lastSeen: now,
        },
        now,
      );

      const tenThousandEvents = service.evaluateRisk(
        {
          incidentId: 'inc-flood-10k',
          severity: EventSeverity.HIGH,
          eventCount: 10000,
          lastSeen: now,
        },
        now,
      );

      // Dampening checks
      expect(singleEvent.components.confidence.velocityScore).toBeLessThan(0.25);
      expect(fiftyEvents.components.confidence.velocityScore).toBe(1.0);
      expect(tenThousandEvents.components.confidence.velocityScore).toBe(1.0); // Strictly capped at 1.0

      // Scores must remain bounded
      expect(tenThousandEvents.score).toBeLessThanOrEqual(100.0);
      expect(tenThousandEvents.score).toBe(fiftyEvents.score); // Saturates without unbounded explosion
    });
  });

  describe('4. Missing Data Behavior & Assumptions Rationale', () => {
    it('gracefully imputes baseline defaults when asset, correlation, and blast radius are missing', () => {
      const now = new Date();
      const breakdown = service.evaluateRisk(
        {
          incidentId: 'inc-missing-data',
          severity: EventSeverity.HIGH,
          lastSeen: now,
        },
        now,
      );

      expect(breakdown.score).toBeDefined();
      expect(breakdown.components.impact.assumedDefaults.length).toBeGreaterThan(0);
      expect(breakdown.components.impact.assetCriticalityScore).toBe(0.50); // Defaulted to MEDIUM
      expect(breakdown.components.impact.environmentModifier).toBe(1.00); // Defaulted to PRODUCTION
      expect(breakdown.components.impact.blastRadiusScore).toBe(0.25); // Defaulted baseline
      expect(breakdown.explanation.some((e) => e.includes('Assumptions:'))).toBe(true);
    });
  });

  describe('5. Temporal Recency Half-Life Decay', () => {
    it('applies exponential decay based on elapsed hours while respecting the decay floor', () => {
      const now = new Date('2026-10-15T12:00:00Z');

      // T = 0 hours (fresh)
      const fresh = service.evaluateRisk(
        {
          incidentId: 'inc-fresh',
          severity: EventSeverity.HIGH,
          lastSeen: new Date('2026-10-15T12:00:00Z'),
        },
        now,
      );

      // T = 24 hours (1 half-life: decay ~ 0.50)
      const oneDayOld = service.evaluateRisk(
        {
          incidentId: 'inc-1d',
          severity: EventSeverity.HIGH,
          lastSeen: new Date('2026-10-14T12:00:00Z'),
        },
        now,
      );

      // T = 72 hours (3 half-lives: should hit decay floor 0.50)
      const threeDaysOld = service.evaluateRisk(
        {
          incidentId: 'inc-3d',
          severity: EventSeverity.HIGH,
          lastSeen: new Date('2026-10-12T12:00:00Z'),
        },
        now,
      );

      expect(fresh.components.recency.decayMultiplier).toBe(1.0);
      expect(oneDayOld.components.recency.decayMultiplier).toBeCloseTo(0.50, 1);
      expect(threeDaysOld.components.recency.decayMultiplier).toBe(0.50); // Floor reached

      expect(fresh.score).toBeGreaterThan(oneDayOld.score);
      expect(oneDayOld.score).toBe(threeDaysOld.score); // Equal due to decay floor
    });
  });
});
