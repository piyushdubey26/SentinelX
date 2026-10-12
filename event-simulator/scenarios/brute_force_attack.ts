/**
 * SentinelX Synthetic Scenario Generator: Brute Force Authentication
 * Sends controlled failed login events to evaluate detection and incident creation.
 */

const API_URL = process.env.API_URL || 'http://localhost:4000/api/v1';

async function runScenario() {
  console.log(`[SIMULATOR] Starting brute force simulation against ${API_URL}`);

  // 1. Authenticate simulator
  const loginRes = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'admin@sentinelx.local',
      password: 'AdminPassword123!',
    }),
  });

  if (!loginRes.ok) {
    throw new Error(`Login failed with status ${loginRes.status}: ${await loginRes.text()}`);
  }

  const loginData = (await loginRes.json()) as any;
  const token = loginData.accessToken;
  console.log(`[SIMULATOR] Authenticated with token: ${token.substring(0, 15)}...`);

  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
  const targetIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
  const targetUser = 'victim_user';

  console.log(`[SIMULATOR] Ingesting 5 failed authentication attempts from IP ${targetIp}...`);

  for (let attempt = 1; attempt <= 5; attempt++) {
    const res = await fetch(`${API_URL}/events/ingest`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        eventType: 'AUTH_FAILURE',
        severity: 'HIGH',
        sourceIp: targetIp,
        targetUser,
        rawPayload: { service: 'ssh', attempt, reason: 'Invalid password' },
      }),
    });

    if (!res.ok) {
      throw new Error(`Ingest attempt ${attempt} failed with status ${res.status}: ${await res.text()}`);
    }

    const data = (await res.json()) as any;
    console.log(
      `[SIMULATOR] Attempt ${attempt}/5: Event ID ${data.event.id} | Detection: ${data.detectionCreated} | Incident: ${data.incidentCreated}`,
    );
  }

  // Verify incident
  const incidentsRes = await fetch(`${API_URL}/incidents?limit=5`, { headers });
  const incidentsData = (await incidentsRes.json()) as any;
  const matchingIncident = incidentsData.data.find((inc: any) => inc.sourceIp === targetIp);
  if (matchingIncident) {
    console.log(`[SIMULATOR] SUCCESS: Created Incident ${matchingIncident.code} (${matchingIncident.title})`);
  } else {
    console.warn('[SIMULATOR] WARNING: No matching incident found for target IP.');
  }
}

runScenario().catch(console.error);
