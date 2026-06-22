# High Availability Threats (T18-T21)

## Overview

Threats T18-T21 are specific to High Availability (HA) deployments and represent architectural risks that only manifest in distributed, multi-instance, or multi-region configurations. These threats are demonstrated in Case Study 2's AWS deployment.

## T18: Split-Brain Scenario

### Description
A split-brain scenario occurs when a distributed system experiences a network partition that divides the cluster into multiple segments, each believing it is the authoritative cluster. This can lead to conflicting operations, data corruption, and inconsistent state across replicas.

### STRIDE Category
- **Tampering**: Data corruption due to conflicting writes
- **Information Disclosure**: Potential exposure of stale/incorrect data
- **Denial of Service**: Service degradation during partition

### Manifestation in HA Quay Deployment

**Auto Scaling Groups**:
- Multiple Quay application instances can scale independently
- No distributed consensus mechanism to coordinate operations
- No quorum configuration to prevent minority partitions from accepting writes

**Database Layer**:
- RDS Aurora automatic failover doesn't coordinate with application layer
- Applications may continue writing to old primary during failover
- No application-level distributed locking

**Load Balancer**:
- ALB routes traffic to all healthy instances regardless of cluster state
- No cluster membership awareness
- Cannot detect partial network partitions

### Detection Methods

1. **Runtime Observation**:
   - Monitor for duplicate resource creation (e.g., two instances creating same resource)
   - Track diverging transaction logs across replicas
   - Detect conflicting writes to shared state (S3, database)

2. **Network Flow Analysis**:
   - Identify communication breakdowns between subnets
   - Monitor for instances unable to reach quorum
   - Track DNS resolution failures for cross-AZ communication

3. **Configuration Analysis**:
   - No distributed consensus protocol (etcd, Consul, ZooKeeper)
   - Missing quorum configuration in ASG
   - No split-brain prevention mechanisms

### Example Scenario

1. Network partition separates AZ-1 from AZ-2 and AZ-3
2. Instances in AZ-1 (minority) continue operating
3. Instances in AZ-2/3 (majority) elect new leader
4. Both groups accept writes independently
5. Partition heals, conflicting state discovered
6. Manual intervention required to resolve conflicts

### Mitigation (Not Implemented)

- Implement distributed consensus (Raft, Paxos)
- Configure minimum quorum size (majority required)
- Use distributed locking (Redis, DynamoDB)
- Implement fencing tokens to prevent stale masters

---

## T19: Cascading Failure

### Description
A cascading failure occurs when the failure of one component triggers failures in dependent components, creating a chain reaction that can bring down the entire system. Without proper circuit breakers and bulkheads, a single point of failure can propagate throughout the architecture.

### STRIDE Category
- **Denial of Service**: Complete service outage due to cascading failures
- **Elevation of Privilege**: Overloaded services may bypass security checks

### Manifestation in HA Quay Deployment

**Zero Deregistration Delay**:
```hcl
deregistration_delay = 0  # Immediate cutover
```
- Failed instances immediately removed from ALB
- Traffic instantly shifted to remaining instances
- Sudden load spike can overwhelm healthy instances
- No graceful degradation period

**No Circuit Breakers**:
- Application directly calls backend services
- No timeout or retry limits configured
- Failed service calls block threads
- Thread pool exhaustion cascades to dependent services

**Immediate ASG Updates**:
- Auto Scaling Group updates apply immediately
- No gradual rollout or canary deployment
- Bad deployment affects all instances simultaneously
- No rollback mechanism for failed updates

**Single Point of Failure**:
- Single ALB fronts all instances
- If ALB fails, entire service unavailable
- No multi-region failover
- No degraded mode operation

### Detection Methods

1. **Runtime Monitoring**:
   - Spike in 5xx errors following single instance failure
   - Exponential increase in error rates
   - Thread pool exhaustion across multiple services
   - Queue depth explosion

2. **Load Pattern Analysis**:
   - Sudden traffic redistribution after instance failure
   - CPU/memory spikes on remaining instances
   - Request timeout increases
   - Connection pool exhaustion

3. **Configuration Review**:
   - `deregistration_delay = 0`
   - No circuit breaker configuration
   - Missing rate limiting
   - No bulkhead isolation

### Example Scenario

1. Single Quay instance fails (e.g., out of memory)
2. ALB immediately deregisters instance (delay = 0)
3. Traffic redistributed to 2 remaining instances
4. Load per instance increases by 50%
5. Increased load causes memory pressure on remaining instances
6. Remaining instances start failing
7. All instances offline within minutes

### Mitigation (Not Implemented)

- Set reasonable `deregistration_delay` (60-300s)
- Implement circuit breakers (Hystrix, resilience4j)
- Use connection pooling with limits
- Implement gradual rollout (blue-green, canary)
- Add rate limiting and request throttling

---

## T20: State Inconsistency Across Replicas

### Description
In a distributed system with multiple replicas, state can become inconsistent when replicas diverge due to replication lag, network issues, or concurrent updates. Without proper consistency mechanisms, clients may observe different data depending on which replica serves their request.

### STRIDE Category
- **Information Disclosure**: Exposure of stale or incorrect data
- **Tampering**: Data corruption from inconsistent updates

### Manifestation in HA Quay Deployment

**Load Balancer - No Session Stickiness**:
```hcl
stickiness {
  enabled = false
}
```
- Each request may route to different Quay instance
- Session state stored locally instead of shared
- User sessions lost between requests
- Inconsistent view of resources

**Redis Replication Lag**:
```hcl
# No replication lag monitoring
# No read-your-writes consistency
```
- Write to primary, read from replica
- Replica lag means recent writes not visible
- Cache invalidation inconsistencies
- Stale data served to clients

**Application State**:
- No distributed cache coordination
- No version vectors or vector clocks
- No conflict resolution strategy
- No read-after-write consistency guarantees

**LLM Model Versions**:
```hcl
# No model version consistency checks
```
- Different LLM instances may have different model versions
- No coordination during model updates
- Inconsistent inference results across replicas
- No model artifact versioning

### Detection Methods

1. **Runtime Testing**:
   - Issue write, immediately read from different instance
   - Compare responses across multiple instances
   - Test session continuity across requests
   - Verify cache coherence

2. **Metrics Analysis**:
   - Measure replication lag (Redis, RDS)
   - Track read-after-write failures
   - Monitor version mismatches
   - Detect conflicting concurrent updates

3. **Configuration Review**:
   - `stickiness.enabled = false`
   - No replication lag alerts
   - Missing consistency level configuration
   - No distributed transaction support

### Example Scenario

1. User uploads container image to Quay instance-1
2. Instance-1 writes metadata to Redis primary
3. Next request routes to instance-2 (no stickiness)
4. Instance-2 reads from Redis replica (replication lag 500ms)
5. User's uploaded image not visible yet
6. User retries, request goes to instance-3
7. Image now visible (inconsistent experience)

### Mitigation (Not Implemented)

- Enable session stickiness on ALB
- Implement read-your-writes consistency
- Use distributed cache (Redis Cluster mode)
- Monitor and alert on replication lag
- Version all shared state (optimistic locking)
- Use consistent hashing for cache keys

---

## T21: Delayed Failure Detection

### Description
In HA systems, the time to detect and respond to failures directly impacts availability. Long health check intervals, grace periods, and passive monitoring can allow failed instances to serve traffic for extended periods, degrading user experience and potentially causing data corruption.

### STRIDE Category
- **Denial of Service**: Degraded service while failed instances serve traffic
- **Information Disclosure**: Exposure of partial/corrupt data from failing instances

### Manifestation in HA Quay Deployment

**Health Check Intervals**:
```hcl
health_check {
  interval = 30  # Quay app
}

health_check {
  interval = 60  # LLM service
}
```
- Failures detected after 30-60 seconds
- Plus 2-3 failed checks before marking unhealthy
- Total detection time: 60-180 seconds
- Failed instance serves traffic during this period

**Long Grace Periods**:
```hcl
health_check_grace_period = 300  # Quay app
health_check_grace_period = 600  # LLM service
```
- New instances not checked for 5-10 minutes
- Failed deployments serve traffic during grace period
- No early failure detection
- Long MTTR (Mean Time To Recovery)

**Passive Health Checks Only**:
- Only load balancer performs health checks
- No active monitoring from instances
- No peer health monitoring
- No cross-region health validation

**Slow AZ Failure Response**:
- AZ failure requires multiple instance failures
- Each instance has own detection window
- Total detection time: minutes to tens of minutes
- No proactive AZ health monitoring

### Detection Methods

1. **Failure Injection Testing**:
   - Kill instance, measure time until traffic stops
   - Simulate AZ failure, measure failover time
   - Induce application errors, measure detection
   - Test network partition scenarios

2. **Metrics Analysis**:
   - Measure time-to-detect for known failures
   - Track error rates before instance deregistration
   - Monitor MTTR across incidents
   - Analyze health check success rates

3. **Configuration Review**:
   - Long `interval` values (>10s)
   - Long `health_check_grace_period` (>60s)
   - High `unhealthy_threshold` (>3)
   - No additional health mechanisms

### Example Scenario

1. Quay instance runs out of disk space
2. Application starts failing requests (time = 0s)
3. First health check fails (time = 30s)
4. Second health check fails (time = 60s)
5. Third health check fails (time = 90s)
6. Instance marked unhealthy, deregistered (time = 90s)
7. Users experienced 90 seconds of errors

**Compounded in HA scenario**:
- If all instances in one AZ fail simultaneously
- Detection time = 90s per instance
- Plus ASG replacement time
- Total recovery time: 5-10 minutes

### Mitigation (Not Implemented)

- Reduce health check intervals (5-10s)
- Implement active health monitoring
- Use multiple health check methods (HTTP + TCP)
- Add application-level health endpoints
- Implement peer monitoring between instances
- Use external monitoring (CloudWatch, Datadog)
- Reduce unhealthy threshold to 2
- Implement proactive failure prediction

---

## Threat Correlation Matrix

| Threat | Related To | Combined Impact |
|--------|-----------|-----------------|
| T18 + T19 | Split-brain triggers cascading failure | System-wide outage with data corruption |
| T18 + T20 | Split-brain causes state divergence | Irreconcilable data conflicts |
| T19 + T21 | Delayed detection allows cascade to spread | Complete service collapse before detection |
| T20 + T21 | Inconsistent state served for extended period | Widespread data corruption |
| T18 + T20 + T21 | All three combined | Catastrophic failure requiring manual recovery |

## Detection Summary

### Static Analysis
- Review Terraform configurations for HA anti-patterns
- Check for missing distributed consensus mechanisms
- Verify health check configurations
- Identify single points of failure

### Runtime Analysis
- Monitor replication lag metrics
- Track error rate spikes correlated with failures
- Measure time-to-detect for instance failures
- Test split-brain scenarios in staging

### Tool Comparison

| Tool | T18 | T19 | T20 | T21 | Notes |
|------|-----|-----|-----|-----|-------|
| Prowler | ❌ | ❌ | ❌ | ❌ | Not architectural |
| Checkov | ❌ | ❌ | ❌ | ❌ | Static IaC only |
| AWS Config Rules | Partial | ❌ | ❌ | Partial | Some HA best practices |
| **Our Framework** | ✅ | ✅ | ✅ | ✅ | Runtime + config analysis |

**Key Insight**: HA-specific threats require runtime observation and architectural analysis. Static security tools cannot detect these threats because they depend on system behavior under failure conditions.

## References

1. Lamport, L. "The Part-Time Parliament" (Paxos algorithm)
2. Ongaro, D. & Ousterhout, J. "In Search of an Understandable Consensus Algorithm" (Raft)
3. AWS Well-Architected Framework - Reliability Pillar
4. Google SRE Book - Cascading Failures
5. Nygard, M. "Release It!" - Circuit Breakers and Stability Patterns
