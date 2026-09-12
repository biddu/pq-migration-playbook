# Rollout and rollback runbook (template)

One runbook per population and per change (for example "edge TLS: enable X25519MLKEM768 first",
"mesh: ML-DSA-65 issuing CA", "signing: LMS for firmware"). The runbook is executed by the on-call
engineer, not the author; every step names the command, the expected observation and the abort
condition. Keep it to one screen per stage.

Change: ____________________  Population: ______________  Policy version: from v__ to v__
Owner: ____________  On-call: ____________  Window: ____________  Rollback owner: ____________

## R0. Preconditions (all must be true before the window)
- [ ] Test plan sections 1-6 PASS for this policy version; report attached: ____________
- [ ] Rollback rehearsed within the last quarter (R3 timings below filled in from the rehearsal)
- [ ] Telemetry alarms live: downgrade events (page), warned-algorithm use (ticket),
      negotiation-failure rate rising within 10 min of a policy digest change (auto-rollback)
- [ ] Baseline recorded: handshake success rate ____ %, p99 ____ ms, negotiated-algorithm mix ____
- [ ] Peer readiness: for a "remove the old path" change, observation shows every client population
      offering the new algorithm for ____ days (source: Chapter 5/6 observers; attach the report)
- [ ] Vendor/dependency state confirmed (HSM firmware, CDN/LB setting, library versions) if applicable

## R1. Canary (stage 1)
1. Push policy v__ to the canary set (____ % of hosts / one region / one service): command ________
2. Confirm reload: policy digest on each canary host == ________ within ____ s
3. Watch for ____ minutes: success rate, p99, negotiated mix, downgrade count, failure rate
   Expected: success rate unchanged (±____), p99 within budget ____ ms, downgrade count 0,
             negotiated mix shows the new algorithm at >= ____ %
   Abort -> R3 if: failure rate up by more than ____ % or any downgrade event or p99 over ____ ms
4. Record observations here: ____________________________________________

## R2. Progressive rollout (stages 2..n)
For each stage (____ %, ____ %, 100 %):
1. Push, confirm digest on all hosts in the stage, watch for ____ minutes with the same criteria
2. Between stages, check the client-side signal too (browser/mobile/SDK error reports, Chapter 6 client warnings)
3. Do not advance if any metric is degraded, even inside budget, until explained
Completion: all hosts at v__, observed mix as expected for ____ hours, baseline updated

## R3. Rollback (any stage; rehearsed)
1. Decide: the abort condition is met, or the report that prompted the change is confirmed -> roll back now
2. Edit policy: add the algorithm to `kill_switch` (or revert to v__), bump version, push: command ________
   Rehearsed time from decision to last host reloaded: ____ s (must be under ____ s)
3. Confirm: digest on all hosts == previous ________; negotiated mix returns to baseline within ____ s
4. Confirm the fallback is the intended one (for a killed hybrid: pure PQ if the policy has it,
   classical only where the floor permits) -- the drill's "victim absent" is not enough
5. Communicate: incident channel, time of rollback, algorithms now in use, exposure statement
6. Post-incident: root cause, whether the drill should have caught it, test plan updates

## R4. Removal of the old path (a separate, later change)
- Precondition: observation shows zero use of the old algorithm by any client population for ____ days
- Change: raise `floor` (or remove the algorithm from `allowed`) in the policy; same R1-R3 stages
- Expected failures: any client that only offered the old algorithm now fails loudly (SSH-style) or
  gets HRR/handshake_failure (TLS); those are the clients the observation missed -- list them, fix them,
  and only then complete

## R5. Evidence to file
- Policy versions and digests before/after; test plan report; canary and stage observations;
  rollback rehearsal timings; CBOM updated with the new algorithm assets and the removed ones
