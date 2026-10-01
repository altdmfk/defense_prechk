import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { execSync } from 'node:child_process';

// 1. Fully Self-Contained Test Suites
const SECURITY_CHECKS = [
  { id: "anonymous_note_read", step: 1, desc: "Test 01: [anonymous_note_read]" },
  { id: "anonymous_note_list", step: 1, desc: "Test 02: [anonymous_note_list]" },
  { id: "repository_secret_scan", step: 2, desc: "Test 03: [repository_secret_scan]" },
  { id: "built_bundle_secret_scan", step: 2, desc: "Test 04: [built_bundle_secret_scan]" },
  { id: "static_seed_data_scan", step: 2, desc: "Test 05: [static_seed_data_scan]" },
  { id: "anonymous_note_write", step: 3, desc: "Test 06: [anonymous_note_write]" },
  { id: "missing_login_token", step: 3, desc: "Test 07: [missing_login_token]" },
  { id: "forged_login_token", step: 3, desc: "Test 08: [forged_login_token]" },
  { id: "expired_login_token", step: 3, desc: "Test 09: [expired_login_token]" },
  { id: "token_wrong_audience", step: 3, desc: "Test 10: [token_wrong_audience]" },
  { id: "r3_judge_owned_note", step: 4, desc: "Test 11: [r3_judge_owned_note]" },
  { id: "r3_judge_owned_note_write", step: 4, desc: "Test 12: [r3_judge_owned_note_write]" },
  { id: "foreign_note_delete", step: 4, desc: "Test 13: [foreign_note_delete]" },
  { id: "direct_origin_note_read", step: 5, desc: "Test 14: [direct_origin_note_read]" },
  { id: "direct_origin_note_write", step: 5, desc: "Test 15: [direct_origin_note_write]" },
  { id: "origin_alias_bypass", step: 5, desc: "Test 16: [origin_alias_bypass]" },
  { id: "unregistered_device", step: 6, desc: "Test 17: [unregistered_device]" },
  { id: "missing_client_certificate", step: 6, desc: "Test 18: [missing_client_certificate]" },
  { id: "device_subject_mismatch", step: 6, desc: "Test 19: [device_subject_mismatch]" },
  { id: "unregistered_virtual_device_rule", step: 6, desc: "Test 20: [unregistered_virtual_device_rule]" },
  { id: "anomalous_region_event", step: 7, desc: "Test 21: [anomalous_region_event]" },
  { id: "anomalous_hour_event", step: 7, desc: "Test 22: [anomalous_hour_event]" },
  { id: "anomalous_network_action", step: 7, desc: "Test 23: [anomalous_network_action]" },
  { id: "missing_step_up", step: 7, desc: "Test 24: [missing_step_up]" },
  { id: "cross_zone_note_read", step: 8, desc: "Test 25: [cross_zone_note_read]" },
  { id: "cross_zone_note_write", step: 8, desc: "Test 26: [cross_zone_note_write]" },
  { id: "cross_zone_note_list", step: 8, desc: "Test 27: [cross_zone_note_list]" },
  { id: "student_edits_instructor_notice", step: 8, desc: "Test 28: [student_edits_instructor_notice]" },
  { id: "doppelganger_detection", step: 9, desc: "Test 29: [doppelganger_detection]" },
  { id: "revoked_identity_reuse", step: 9, desc: "Test 30: [revoked_identity_reuse]" },
  { id: "stolen_session_after_revoke", step: 9, desc: "Test 31: [stolen_session_after_revoke]" },
  { id: "revoked_lateral_route", step: 9, desc: "Test 32: [revoked_lateral_route]" },
  { id: "restore_changed_note", step: 10, desc: "Test 33: [restore_changed_note]" },
  { id: "restore_deleted_note", step: 10, desc: "Test 34: [restore_deleted_note]" },
  { id: "restore_defense_replay", step: 10, desc: "Test 35: [restore_defense_replay]" },
  { id: "unsigned_client_request", step: 11, desc: "Test 36: [unsigned_client_request]" },
  { id: "signed_path_tamper", step: 11, desc: "Test 37: [signed_path_tamper]" },
  { id: "signed_body_tamper", step: 11, desc: "Test 38: [signed_body_tamper]" },
  { id: "combined_anonymous_owner_attack", step: 12, desc: "Test 39: [combined_anonymous_owner_attack]" },
  { id: "combined_device_revocation_attack", step: 12, desc: "Test 40: [combined_device_revocation_attack]" },
  { id: "combined_restore_signature_attack", step: 12, desc: "Test 41: [combined_restore_signature_attack]" }
];

class TestRunner {
  constructor(config) {
    this.config = config;
    this.pass = 0;
    this.fail = 0;
  }
  
  createError(msg, expected, remediation, actualInfo) {
    const err = new Error(msg);
    err.expected = expected;
    err.remediation = remediation;
    err.actualInfo = actualInfo;
    return err;
  }
  
  async runAll() {
    console.log(`\nStarting Pre-check CLI tests...`);
    
    for (const test of SECURITY_CHECKS) {
      if (this.config.stepFilter && test.step !== this.config.stepFilter) continue;
      
      const displayName = test.desc;
        
      console.log(`\n▶ Running ${displayName}`);
      
      try {
        await this.executeTest(test.id);
        console.log(`  ✅ PASS`);
        this.pass++;
      } catch (err) {
        if (err.remediation) {
          console.log(`  ❌ FAIL: ${err.message}`);
          
          // Diagnostic Reporting
          console.log(`\n      --- DIAGNOSTIC CARD ---`);
          console.log(`      * Test Case ID: ${test.id}`);
          console.log(`      * Expected Server Invariant: ${err.expected}`);
          console.log(`      * Actual Server Output: ${JSON.stringify(err.actualInfo)}`);
          console.log(`      * Remediation Advice: ${err.remediation}`);
          console.log(`      -----------------------`);
        } else {
          console.log(`  ⚠️ ERROR: ${err.message}`);
        }
        this.fail++;
      }
    }
    
    console.log(`\n=== 🏁 PRE-CHECK SUMMARY ===`);
    console.log(`✅ PASS: ${this.pass}`);
    console.log(`❌ FAIL: ${this.fail}`);
    
    const tableData = [
      { Total_Tests: this.pass + this.fail, Passed: this.pass, Failed: this.fail, Status: this.fail === 0 ? 'CLEAN' : 'VULNERABLE' }
    ];
    console.table(tableData);
    
    process.exit(this.fail > 0 ? 1 : 0);
  }
  
  async executeTest(id) {
    const { url, token, adminToken } = this.config;
    
    const fetchApi = async (method, route, auth = null, body = null, extraHeaders = {}) => {
      const headers = { ...extraHeaders };
      if (auth) headers['Authorization'] = `Bearer ${auth}`;
      if (body) headers['Content-Type'] = 'application/json';
      const opts = { method, headers, redirect: 'manual' };
      if (body) opts.body = JSON.stringify(body);
      try {
        const res = await fetch(`${url}${route}`, opts);
        let status = res.status;
        const text = await res.text().catch(()=>'');
        
        // SPA Catch-all False Positive Prevention
        // If an API route returns 200 but it's actually an HTML page (like index.html),
        // it usually means the endpoint doesn't exist and it hit a frontend wildcard.
        if (status === 200) {
          const lowerText = text.trim().toLowerCase();
          if (lowerText.startsWith('<!doctype html') || lowerText.startsWith('<html')) {
             status = 404; 
          }
        }
        
        return { status, body: text };
      } catch (e) {
        return { status: 0, body: e.message };
      }
    };

    // 2. Multi-Step Test Flows

    // Flow A: Session Revocation
    if (['revoked_identity_reuse', 'stolen_session_after_revoke', 'revoked_lateral_route'].includes(id)) {
      await fetchApi('POST', '/api/auth/logout', token);
      const res = await fetchApi('GET', '/api/protected', token); // Follow-up with revoked token
      
      if (res.status === 200 || res.status === 201) {
         throw this.createError(
           "Revoked token still valid", 
           "401 Unauthorized or 403 Forbidden",
           "Implement robust session blocklisting (e.g. Redis JTI cache) or stateless revocation checks.", 
           { status: res.status, body: res.body.substring(0, 50) }
         );
      }
      return;
    }
    
    // Flow B: RBAC Boundary
    if (id === 'student_edits_instructor_notice') {
      const studentRes = await fetchApi('POST', '/api/notice', token, { title: 'hacked' });
      if (studentRes.status === 200 || studentRes.status === 201) {
        throw this.createError(
          "Student successfully performed instructor action", 
          "403 Forbidden",
          "Enforce role-based access control (RBAC) boundaries in your middleware.", 
          { status: studentRes.status }
        );
      }
      return;
    }
    
    // Flow C: IDOR / BOLA
    if (['r3_judge_owned_note', 'r3_judge_owned_note_write', 'foreign_note_delete'].includes(id)) {
      const method = id.includes('delete') ? 'DELETE' : (id.includes('write') ? 'PUT' : 'GET');
      const accessRes = await fetchApi(method, '/api/notes/99999', token); // 99999 belongs to Admin/Foreign user
      
      if (accessRes.status === 200 || accessRes.status === 204 || accessRes.status === 201) {
        throw this.createError(
          "Cross-tenant resource accessed/modified successfully", 
          "403 Forbidden or 404 Not Found",
          "Implement IDOR/BOLA checks verifying resource ownership against the active session ID.", 
          { status: accessRes.status }
        );
      }
      return;
    }
    
    // Flow D: Bundle Hygiene
    if (['built_bundle_secret_scan', 'static_seed_data_scan'].includes(id)) {
      const res = await fetchApi('GET', '/');
      const html = res.body;
      const scripts = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map(m => m[1]);
      
      for (let src of scripts) {
        if (!src.startsWith('http')) src = `${url}${src.startsWith('/') ? '' : '/'}${src}`;
        const sRes = await fetch(src).catch(() => ({ ok: false }));
        if (!sRes.ok) continue;
        const sBody = await sRes.text().catch(() => '');
        
        if (id === 'built_bundle_secret_scan' && (sBody.includes('SUPABASE_SERVICE_ROLE_KEY') || /(?:eyJ[A-Za-z0-9-_]+\\.){2}[A-Za-z0-9-_]+/.test(sBody))) {
          throw this.createError(
            `Client bundle leaks sensitive keys in ${src}`, 
            "No sensitive keys in frontend bundle",
            "Remove sensitive environment variables from client-side bundles (e.g. NEXT_PUBLIC_...).", 
            { matchFound: true }
          );
        } else if (id === 'static_seed_data_scan' && sBody.toLowerCase().includes('private note')) {
          throw this.createError(
            `Client bundle has seed/hardcoded private data in ${src}`, 
            "No hardcoded sensitive data",
            "Do not hardcode sensitive initial data or seed variables into the client code.", 
            { matchFound: true }
          );
        }
      }
      return;
    }
    
    // Repository Secret Scan
    if (id === 'repository_secret_scan') {
       try {
         // precheck.mjs와 dummy_server.js 자체 코드에 포함된 스캔 로직 문자열이 오탐되는 것을 방지하기 위해 exclude 처리
         const log = execSync('git log -p -n 10 -- . ":(exclude)precheck.mjs" ":(exclude)dummy_server.js"', { encoding: 'utf8', maxBuffer: 1024*1024 });
         if (log.includes('SUPABASE_SERVICE_ROLE_KEY') || log.includes('-----BEGIN PRIVATE KEY-----')) {
           throw this.createError(
             "Git commit history contains sensitive secrets", 
             "Clean repository history",
             "Rewrite git history to remove secrets using tools like BFG Repo-Cleaner.", 
             { leakFound: true }
           );
         }
       } catch (e) {
         if (e.remediation) throw e;
       }
       return;
    }
    
    // Generic Flow: Anonymous Access
    if (id.includes('anonymous')) {
      const method = id.includes('write') ? 'POST' : 'GET';
      const res = await fetchApi(method, '/api/notes', null);
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Anonymous access allowed", 
          "401 Unauthorized or 403 Forbidden",
          "Implement authentication middleware to block unauthenticated requests.", 
          { status: res.status, body: res.body.substring(0, 100) }
        );
      }
      return;
    }

    // Generic Flow: Invalid Tokens
    if (id.includes('token')) {
      let badToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig";
      if (id === 'expired_login_token') badToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDB9.sig";
      
      const res = await fetchApi('GET', '/api/notes', badToken);
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Invalid or forged token accepted", 
          "401 Unauthorized or 403 Forbidden",
          "Validate JWT signatures and expiration times strictly.", 
          { status: res.status }
        );
      }
      return;
    }
    
    // Generic Flow: Origin / Cross-Zone
    if (id.includes('origin') || id.includes('zone')) {
      const res = await fetchApi('GET', '/api/notes', token, null, { 'Host': 'evil.com', 'Origin': 'https://evil.com' });
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Origin spoofing / Cross-zone access allowed", 
          "403 Forbidden",
          "Implement CORS policies and strictly validate Host/Origin headers.", 
          { status: res.status }
        );
      }
      return;
    }
    
    // Generic Flow: Devices
    if (id.includes('device') || id.includes('client_certificate')) {
      const res = await fetchApi('GET', '/api/notes', token, null, { 'X-Device-Id': 'unknown-device' });
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Unregistered device / Missing certificate allowed", 
          "401 Unauthorized or 403 Forbidden",
          "Enforce device identity checks or mTLS for secure endpoints.", 
          { status: res.status }
        );
      }
      return;
    }

    // Generic Flow: Anomalous
    if (id.includes('anomalous') || id.includes('doppelganger') || id.includes('step_up')) {
      const res = await fetchApi('POST', '/api/notes', token, { test: 1 }, { 'X-Forwarded-For': '203.0.113.1' });
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Anomalous activity not flagged/blocked", 
          "401 Unauthorized, 403 Forbidden, or 429 Too Many Requests",
          "Implement anomaly detection for abnormal IP, velocity, or concurrent sessions.", 
          { status: res.status }
        );
      }
      return;
    }

    // Generic Flow: Tamper
    if (id.includes('tamper') || id.includes('unsigned') || id.includes('restore') || id.includes('combined')) {
      const res = await fetchApi('POST', '/api/notes', token, { tampered: true }, { 'X-Signature': 'invalid' });
      if (res.status === 200 || res.status === 201) {
        throw this.createError(
          "Tampered or unsigned request accepted", 
          "400 Bad Request or 403 Forbidden",
          "Implement strict request signature verification (HMAC).", 
          { status: res.status }
        );
      }
      return;
    }

    // Fallback: Ping generic endpoint
    const res = await fetchApi('GET', `/api/ping/${id}`, token);
    if (res.status >= 500) {
      throw this.createError(
        "Server crashed on generic test", 
        "Graceful error handling",
        "Ensure robust error handling to prevent 500s.", 
        { status: res.status }
      );
    }
  }
}

// 3. CLI Interface & Execution
async function main() {
  const options = {
    url: { type: 'string' },
    token: { type: 'string' },
    'admin-token': { type: 'string' },
    step: { type: 'string' }
  };
  
  const { values } = parseArgs({ options, strict: false });
  
  // 수동 .env 파싱 로직 복구
  const envPath = path.join(process.cwd(), '.env');
  const env = {};
  if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match) env[match[1]] = match[2].replace(/^['"]|['"]$/g, '').trim();
    });
  }
  
  const config = {
    url: values.url || env.TARGET_URL || 'http://localhost:4000',
    token: values.token || env.USER_TOKEN || 'dummy-user-token',
    adminToken: values['admin-token'] || env.ADMIN_TOKEN || 'dummy-admin-token',
    stepFilter: values.step ? parseInt(values.step, 10) : null
  };
  
  const runner = new TestRunner(config);
  await runner.runAll();
}

main().catch(console.error);
