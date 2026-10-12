import { DataSource } from 'typeorm';
import { Role } from '../src/users/entities/role.entity';
import { User } from '../src/users/entities/user.entity';
import { Asset } from '../src/assets/entities/asset.entity';
import { SecurityEvent, EventSeverity } from '../src/events/entities/security-event.entity';
import { Detection } from '../src/detections/entities/detection.entity';
import { Incident, IncidentStatus } from '../src/incidents/entities/incident.entity';
import { AuditLog } from '../src/audit/entities/audit-log.entity';

describe('Milestone 1.2: PostgreSQL Schema & Constraints Integration Tests', () => {
  let dataSource: DataSource;

  beforeAll(async () => {
    dataSource = new DataSource({
      type: 'postgres',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USERNAME || 'piyushdubey',
      password: process.env.DB_PASSWORD || '',
      database: 'sentinelx_test',
      entities: [Role, User, Asset, SecurityEvent, Detection, Incident, AuditLog],
      synchronize: false,
    });
    await dataSource.initialize();
  });

  afterAll(async () => {
    if (dataSource && dataSource.isInitialized) {
      await dataSource.destroy();
    }
  });

  it('should verify roles table has default seeded roles', async () => {
    const roleRepo = dataSource.getRepository(Role);
    const roles = await roleRepo.find();
    expect(roles.length).toBeGreaterThanOrEqual(4);
    const roleNames = roles.map((r) => r.name);
    expect(roleNames).toContain('ADMIN');
    expect(roleNames).toContain('SOC_ANALYST');
  });

  it('should enforce unique constraint on user email', async () => {
    const userRepo = dataSource.getRepository(User);
    const adminRole = await dataSource.getRepository(Role).findOneBy({ name: 'ADMIN' as any });
    expect(adminRole).toBeDefined();

    const duplicateUser = userRepo.create({
      email: 'admin@sentinelx.local', // Already seeded
      passwordHash: 'dummy',
      firstName: 'Dup',
      lastName: 'User',
      roleId: adminRole!.id,
    });

    await expect(userRepo.save(duplicateUser)).rejects.toThrow();
  });

  it('should enforce foreign key constraint on users.role_id', async () => {
    const userRepo = dataSource.getRepository(User);
    const invalidUser = userRepo.create({
      email: `test-${Date.now()}@sentinelx.local`,
      passwordHash: 'dummy',
      firstName: 'Invalid',
      lastName: 'Role',
      roleId: '00000000-0000-0000-0000-000000000000', // Non-existent FK
    });

    await expect(userRepo.save(invalidUser)).rejects.toThrow();
  });

  it('should create and link a security event, detection, and incident', async () => {
    const eventRepo = dataSource.getRepository(SecurityEvent);
    const detectionRepo = dataSource.getRepository(Detection);
    const incidentRepo = dataSource.getRepository(Incident);

    // 1. Create Security Event
    const event = await eventRepo.save({
      eventType: 'AUTH_FAILURE',
      severity: EventSeverity.HIGH,
      sourceIp: '192.168.1.100',
      targetUser: 'root',
      rawPayload: { reason: 'bad_password' },
      normalizedDetails: { attempt: 1 },
      eventTimestamp: new Date(),
    });
    expect(event.id).toBeDefined();

    // 2. Create Detection
    const detection = await detectionRepo.save({
      ruleId: 'RULE-BRUTE-FORCE-001',
      ruleName: 'Brute Force Authentication Pattern',
      severity: EventSeverity.HIGH,
      sourceIp: '192.168.1.100',
      targetUser: 'root',
      triggerCount: 5,
      timeWindowSeconds: 60,
      evidence: { eventIds: [event.id] },
    });
    expect(detection.id).toBeDefined();

    // 3. Create Incident linked to Detection
    const incidentCode = `INC-TEST-${Date.now()}`;
    const incident = await incidentRepo.save({
      code: incidentCode,
      title: 'Repeated Authentication Failures (Brute Force)',
      summary: 'Automated detection triggered for source IP 192.168.1.100',
      severity: EventSeverity.HIGH,
      status: IncidentStatus.OPEN,
      sourceIp: '192.168.1.100',
      detectionId: detection.id,
    });
    expect(incident.id).toBeDefined();
    expect(incident.detectionId).toBe(detection.id);

    // Cleanup test records
    await incidentRepo.delete({ id: incident.id });
    await detectionRepo.delete({ id: detection.id });
    await eventRepo.delete({ id: event.id });
  });

  it('should persist audit log without sensitive credentials', async () => {
    const auditRepo = dataSource.getRepository(AuditLog);
    const audit = await auditRepo.save({
      action: 'SECURITY_CHECK_EXECUTION',
      resourceType: 'TEST_SUITE',
      resourceId: 'test-case-001',
      ipAddress: '127.0.0.1',
      details: { outcome: 'PASSED' },
    });
    expect(audit.id).toBeDefined();
    expect(audit.details).toEqual({ outcome: 'PASSED' });
    // Verify no password fields exist
    expect((audit.details as any).password).toBeUndefined();

    await auditRepo.delete({ id: audit.id });
  });
});
