/**
 * SentinelX Synthetic Scenario Generator: Brute Force Authentication
 * Sends controlled failed login events to evaluate detection and incident creation.
 */

import axios from 'axios';

const API_URL = process.env.API_URL || 'http://localhost:4000/api/v1';

async function runScenario() {
  console.log(`[SIMULATOR] Starting brute force simulation against ${API_URL}`);

  // 1. Authenticate simulator
  const loginRes = await axios.post(`${API_URL}/auth/login`, {
    email: 'admin@sentinelx.local',
    password: 'AdminPassword123!',
  });
  const token = loginRes.data.accessToken;
  console.log(`[SIMULATOR] Authenticated with token: ${token.substring(0, 15)}...`);

  const headers = { Authorization: `Bearer ${token}` };
  const targetIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
  const targetUser = 'victim_user';

  console.log(`[SIMULATOR] Ingesting 5 failed authentication attempts from IP ${targetIp}...`);

  for (let attempt = 1; attempt <= 5; attempt++) {
    const res = await axios.post(
      `${API_URL}/events/ingest`,
      {
        eventType: 'AUTH_FAILURE',
        severity: 'HIGH',
        sourceIp: targetIp,
        targetUser,
        rawPayload: { service: 'ssh', attempt, reason: 'Invalid password' },
      },
      { headers },
    );

    console.log(
      `[SIMULATOR] Attempt ${attempt}/5: Event ID ${res.data.event.id} | Detection: ${res.data.detectionCreated} | Incident: ${res.data.incidentCreated}`,
    );
  }

  // Verify incident
  const incidentsRes = await axios.get(`${API_URL}/incidents?limit=5`, { headers });
  const matchingIncident = incidentsRes.data.data.find((inc: any) => inc.sourceIp === targetIp);
  if (matchingIncident) {
    console.log(`[SIMULATOR] SUCCESS: Created Incident ${matchingIncident.code} (${matchingIncident.title})`);
  } else {
    console.warn('[SIMULATOR] WARNING: No matching incident found for target IP.');
  }
}

runScenario().catch(console.error);
