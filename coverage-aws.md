# AWS Coverage Gaps — Tracking Checklist

Working document to drive incremental additions to the AWS provider.

**Scope**: what is *collected* (fetched into the inventory), not what is *ruled on*. A missing
collector means no rule can ever be written; a missing rule on existing data is a separate,
much cheaper problem.

**Baseline**: 31 services collected in the open-source tree
(`ScoutSuite/providers/aws/resources/`). Four more — `cognito`, `docdb`, `guardduty`, `ssm` —
exist only as `private_*` modules and are therefore **not available** in this tree
(see the `try/except ImportError` blocks in `ScoutSuite/providers/aws/services.py`).

**How to add a service** (pattern to follow, e.g. `vpc`):

1. `ScoutSuite/providers/aws/facade/<svc>.py` — a `<Svc>Facade(AWSBaseFacade)` with `async` getters
2. register it in `ScoutSuite/providers/aws/facade/base.py`
3. `ScoutSuite/providers/aws/resources/<svc>/base.py` (+ one file per resource type)
4. instantiate in `AWSServicesConfig.__init__` (`ScoutSuite/providers/aws/services.py`)
5. add the service to `ScoutSuite/providers/aws/metadata.json` under the right group
6. add the required IAM read permissions to the documented policy
7. write rules under `ScoutSuite/providers/aws/rules/findings/` and wire them into
   `rules/rulesets/default.json` / `detailed.json`

---

## P0 — Quick wins (facade code already exists or is trivial)

- [x] **VPC route tables** — done. Route tables are collected per VPC
      (`vpc.regions.id.vpcs.id.route_tables`), read once per region and cached, as every subnet of
      the region needs them too. Unlocks the single most useful derived attribute in the whole
      model: **public vs private subnet** (an active `0.0.0.0/0` or `::/0` route to an `igw-*`
      target).
      - [x] routes flattened to a destination and a target with the type of each, associated
            subnets and gateways, main-table flag, propagating VGWs, blackhole routes, peering
            routes broader than the largest possible VPC CIDR block
      - [x] `is_public` and `route_table_id` derived on subnets, `in_public_subnet` propagated to
            EC2 instances, network interfaces and ELB load balancers
      - [ ] left out: propagation to RDS instances (whose subnets come through a DB subnet group),
            ELBv2 load balancers (which do not collect their subnets) and Lambda-in-VPC
- [x] **Region opt-in status** — done. `account:ListRegions` is collected as
      `account.region_opt_status`, giving every region of the partition with the account's opt-in
      status for it, and the derived `enabled` / `enabled_by_default` / `enabled_by_opt_in` flags.
      A rule flags the regions enabled by opt-in, which carry the same exposure as the default ones
      without having been part of any original design and can be turned off again.
      - [ ] left out: using the result to scope the scan, `build_region_list()` still calling
            `ec2:DescribeRegions` on its own.
- [x] **EC2 account-level defaults** — done, under `ec2.regions.id.regional_settings` next to the
      EBS default encryption and key that were already there.
      - [x] account-level IMDS defaults (`GetInstanceMetadataDefaults`: IMDSv2 required, hop limit),
            collected with the launch templates and now ruled on
      - [x] `GetSnapshotBlockPublicAccessState` (blocks public snapshot sharing region-wide)
- [x] **Elastic IPs** (`DescribeAddresses`) — done, as `ec2.regions.id.elastic_ips`: the address,
      allocation, pool, network border group and whether AWS manages it on behalf of a service, plus
      the association (instance, network interface and its owner, private address, subnet). The
      public IP → ENI → instance mapping is applied back onto instances and network interfaces in
      preprocessing, as `elastic_ips`. A rule flags the addresses attached to nothing.
- [x] **EC2 key pairs** (`DescribeKeyPairs`) — done, as `ec2.regions.id.key_pairs`: creation date,
      type (RSA/ED25519), fingerprint and tags. Usage is resolved in preprocessing against the
      instances, the launch template versions and the launch configurations, none of which is
      visible from the key pair. Two rules: a key pair nothing refers to, and one older than a
      configurable number of days (365 by default), a key pair having no rotation in place.

## P1 — Account governance and detection

The largest structural gap: ScoutSuite currently has almost no view of *preventive* guardrails
or of whether AWS's own detection services are switched on.

- [ ] **Organizations** — new service. Only
      `IAMFacade.get_organizations_root_credentials_managed()`
      (`ScoutSuite/providers/aws/facade/iam.py:59`) touches Organizations today.
      - [ ] org description, management account, enabled policy types, `FeatureSet` (ALL vs CONSOLIDATED_BILLING)
      - [ ] OU tree and member accounts (status, joined date, email)
      - [ ] **SCPs** — content, targets, effective attachment per account/OU
      - [ ] RCPs (resource control policies), declarative policies, tag policies, backup policies
      - [ ] delegated administrators and delegated services
      - [ ] AI services opt-out policy
- [x] **IAM Access Analyzer** — done, as the new `accessanalyzer` service. AWS's authoritative
      answer to "what is shared outside this account", covering resource types ScoutSuite does not
      policy-analyse at all. Whether a region is analysed is a property of the region, so the
      per-kind analyzer counters a rule fires on when there is no analyzer to attach a finding to
      are derived after the fetch, in `resources/accessanalyzer/base.py::_set_coverage`.
      - [x] analyzers per region (ACCOUNT / ORGANIZATION / \*_UNUSED_ACCESS / \*_INTERNAL_ACCESS,
            reduced to a `kind` and an `organization_wide` flag), status and its reason, whether an
            AWS service manages it, last resource analyzed, the unused-access tracking period and
            its exclusions, the internal-access inclusions
      - [x] external-access findings, with the detail each one needs to mean anything: the
            principals and their types, the actions, the condition keys, the sources (policy,
            bucket ACL, access point), `isPublic`, and whether a resource or service control policy
            already blocks the access
      - [x] unused-access findings (unused roles, unused permissions, unused passwords and access
            keys), from the listing only, since the resource they name identifies them fully
      - [x] internal-access findings, opportunistically: the API returns them through the same call
            and they carry the same detail structure
      - [x] archive rules with their filter criteria, and the derived
            `archives_public_access` — a rule matching on `isPublic` files away public exposure
            before anybody sees it
      - [ ] left out: `GetFindingV2` for the unused-access findings, which would add the
            `lastAccessed` date and the unused action list; `ListAnalyzedResources`, which would say
            which resources an analyzer covers rather than which ones it flagged; access previews;
            and `ValidatePolicy` / `GetGeneratedPolicy`, which analyse a policy handed to them
            rather than the account
      - [ ] left out (rules): the unused password and access key findings, since
            `iam-unused-credentials-not-disabled` already covers them from the credential report;
            and the unused-access exclusions, which hide accounts and tagged roles the same way an
            archive rule hides findings
- [ ] **GuardDuty** — currently `private_guardduty` only; port an open-source collector.
      - [ ] detector per region, enabled state, finding publishing frequency
      - [ ] feature/data-source coverage (S3 logs, EKS audit logs, malware protection, RDS login events, Lambda network logs, runtime monitoring)
      - [ ] org-level auto-enable configuration, member accounts
      - [ ] suspended/disabled detectors, IP sets / threat intel sets
- [ ] **Security Hub** — new service. Referenced only as a *rule reference* in
      `rules/findings/*.json`; nothing is collected.
      - [ ] hub per region, enabled state, auto-enable controls, consolidated findings mode
      - [ ] enabled standards (CIS, AWS FSBP, PCI DSS, NIST) and per-control status
      - [ ] finding aggregation region, org configuration, delegated admin
- [ ] **AWS Backup** — new service. Resilience is currently only visible per service
      (RDS backup retention, DynamoDB PITR); there is no cross-service view.
      - [ ] backup vaults, **vault lock** (governance vs compliance mode, retention)
      - [ ] vault access policies (cross-account share = exfil path)
      - [ ] backup plans, rules, copy actions, cross-region/cross-account copies
      - [ ] protected resources / coverage gaps, backup vault notifications
- [ ] **Inspector v2** — enablement per region and per scan type (EC2, ECR, Lambda code/standard),
      plus suppression rules.
- [ ] **Macie** — enablement, automated sensitive-data discovery status, classification job coverage
      of S3 buckets.
- [ ] **Detective** — graph existence and member accounts (low value alone, cheap alongside GuardDuty).
- [ ] **CloudTrail — beyond classic trails**. `resources/cloudtrail/trails.py` collects only
      regular trails.
      - [ ] organization trails (`IsOrganizationTrail`) distinguished from account trails
      - [ ] CloudTrail Lake event data stores (retention, termination protection, KMS)
      - [ ] advanced event selectors (data events on S3/Lambda/DynamoDB), insight selectors
      - [ ] channels for CloudTrail integrations
- [ ] **AWS Config — beyond recorders and rules**. `resources/config/` has
      `recorders.py` + `rules.py` only.
      - [ ] delivery channels (target bucket/SNS, delivery frequency) — a recorder with a broken
            delivery channel records nothing usable
      - [ ] conformance packs and their compliance status
      - [ ] configuration aggregators (and their authorizations)
      - [ ] retention configuration, recorder resource-type exclusions

## P2 — Exposure surface (network and application)

- [ ] **API Gateway v1 (REST)** — new service. Currently the single largest application-exposure
      blind spot: an entire public API tier is invisible to the scanner.
      - [ ] REST APIs, endpoint configuration (EDGE / REGIONAL / **PRIVATE**), disable-execute-api-endpoint
      - [ ] **resource policies** (who can invoke, VPCE conditions)
      - [ ] authorizers (NONE / IAM / Cognito / Lambda) per method, API keys required
      - [ ] stages: access logging, execution logging level, X-Ray, cache + cache encryption, WAF ACL association, client certificate
      - [ ] usage plans / throttling, custom domains + minimum TLS policy, mutual TLS
      - [ ] VPC links, private integrations
- [ ] **API Gateway v2 (HTTP / WebSocket)** — same axes; distinct API and paging model.
      - [ ] APIs, protocol type, auto-deploy, CORS configuration (`*` origins)
      - [ ] JWT / Lambda authorizers, routes with `AuthorizationType: NONE`
      - [ ] stage access logging, custom domains + TLS policy, mutual TLS
- [x] **WAF / WAFv2** — done, as the `waf` service (boto3 `wafv2`).
      - [x] Web ACLs of both scopes, the CLOUDFRONT ones reported under `us-east-1` which is the
            endpoint serving them, with default action, rules, managed and referenced rule groups,
            rate-based statements, count-mode rules and rule action overrides, and the account's own
            rule groups as a separate resource
      - [x] **associated resources** of every type `ListResourcesForWebACL` answers for, CloudFront
            distributions resolved through `ListDistributionsByWebACLId` — and, by difference, the
            web ACL reported on each ELBv2 load balancer and CloudFront distribution, so an exposed
            resource with **no** ACL is a finding of its own
      - [x] logging configuration, log destinations, redacted fields and data protections, logging
            filter, sampled-requests and CloudWatch metrics settings of the ACL and of each rule
      - [ ] IP sets, regex pattern sets and the permission policies sharing a rule group across
            accounts
      - [ ] classic WAF / WAF Regional — not collected, the service reached end of support and the
            accounts still holding one cannot create another
- [ ] **Shield Advanced** — subscription state, protected resources, proactive engagement,
      emergency contacts.
- [ ] **Internet gateways / NAT gateways / egress-only IGWs** — needed to close the route-table
      story and to distinguish "no route out" from "NAT'd".
- [ ] **Transit Gateway** — TGWs, attachments (VPC / VPN / peering / Connect), TGW route tables,
      associations and propagations, auto-accept-shared-attachments, cross-account attachments.
      Lateral-movement topology that is entirely absent today.
- [ ] **Site-to-Site VPN** — connections, tunnel options (IKE versions, DH groups, PSK vs cert),
      tunnel state, logging; customer gateways; VGWs.
- [ ] **Client VPN** — endpoints, authentication type, **authorization rules** (all-groups access),
      split-tunnel, connection logging, self-service portal.
- [ ] **Security group rules as first-class objects** (`DescribeSecurityGroupRules`) —
      `resources/ec2/securitygroups.py` parses the embedded permissions, which loses rule IDs,
      per-rule descriptions and tags. Needed for actionable remediation output and for
      referenced-prefix-list rules.
- [ ] **Managed prefix lists** — a rule referencing a prefix list is currently opaque: the CIDRs
      behind it are never resolved, so a `0.0.0.0/0` hidden in a prefix list is invisible.
- [ ] **Network Firewall** — firewalls, policies, stateless/stateful rule groups, logging
      configuration, subnet associations, delete/subnet-change protection.
- [ ] **Route 53 Resolver** — resolver endpoints (inbound/outbound), rules and shares,
      **DNS Firewall** rule groups + associations, **query logging** configurations.
- [ ] **Route 53 DNSSEC** — signing status and KSKs per hosted zone; `resources/route53/`
      collects zones, records and registered domains only. Also worth adding: dangling
      records pointing at deprovisioned targets (subdomain takeover) and registrar transfer lock.
- [ ] **Global Accelerator** — accelerators, listeners, endpoint groups, flow logs.
- [ ] **VPC Lattice** — service networks, services, auth policies, access-log subscriptions.
- [ ] **ACM Private CA** — CAs, status, policies (cross-account issuance), audit reports,
      CRL/OCSP configuration.

## P3 — Compute, data and CI/CD services not collected

- [x] **Auto Scaling groups + launch templates + launch configurations** — done. Launch templates
      are collected as an EC2 resource (`ec2.regions.id.launch_templates`), Auto Scaling groups and
      launch configurations as the new `autoscaling` service. What creates the next instances is now
      read the same way as the existing ones.
      - [x] launch templates, default and latest version of each: **user data** (same secret scan as
            instances), `MetadataOptions` (IMDSv2 and hop limit), AMI id, instance profile, security
            groups, `AssociatePublicIpAddress`, per-device EBS encryption and KMS key, key pair,
            monitoring, tenancy, API termination and stop protection, and whether the default version
            is still the latest one. The region's instance metadata defaults are collected alongside,
            under the EC2 regional settings, as they decide what a template that says nothing gets.
      - [x] launch configurations (legacy): same fields, minus what launch configurations never
            supported.
      - [x] ASGs: subnets and availability zones, launch template (including inside a mixed instances
            policy) or launch configuration and the pinned version, health check type and grace
            period, load balancers, target groups and traffic sources, suspended processes, enabled
            metrics, termination policies, maximum instance lifetime, maintenance policy, scale-in
            protection and tag propagation.
      - [ ] left out: intermediate launch template versions (a template can hold thousands and none
            of them is in force), instance refresh history, and resolving the subnets of a group
            against the route tables to tell public from private.
- [ ] **SSM / Systems Manager** — `private_ssm` only; port an open-source collector.
      - [ ] **Parameter Store**: parameters, type (`String` vs `SecureString`), KMS key, tier,
            policies — a secret in a plain `String` parameter is a classic finding
      - [ ] documents owned by the account, and **documents shared publicly** (`Public` share)
      - [ ] Session Manager preferences: logging to S3/CloudWatch, KMS encryption, run-as user
      - [ ] managed instances inventory + patch compliance state, patch baselines (approval rules,
            auto-approval delay), maintenance windows
      - [ ] State Manager associations, `AmazonLinux`/inventory collection
- [ ] **OpenSearch Service (and legacy Elasticsearch Service)** — domains, **public vs VPC access**,
      access policies, fine-grained access control / internal user database, encryption at rest,
      node-to-node encryption, TLS policy, audit/slow logs, version and EOL status, cold/warm tiers.
- [ ] **Cognito** — `private_cognito` only; port an open-source collector. User pools (MFA, password
      policy, advanced security mode, deletion protection), app clients (secret, allowed OAuth flows,
      callback URLs, token validity, prevent-user-existence-errors), identity pools
      (**unauthenticated identities allowed**, attached roles and their trust policies, classic flow).
- [x] **Amazon MSK / Kafka** — done, as the `msk` service (boto3 `kafka`): provisioned and
      serverless clusters, encryption in transit (client-broker + in-cluster), at-rest KMS key and
      whether it is customer managed, client authentication (IAM/SCRAM/mTLS/unauthenticated), SCRAM
      secrets, public access and multi-VPC connectivity, cluster policy, broker logs, monitoring
      level, Kafka version support status, and the server properties of the configuration each
      cluster runs (`allow.everyone.if.no.acl.found`, `auto.create.topics.enable`), plus the region's
      MSK configurations as a separate resource.
- [ ] **Kinesis Data Streams / Firehose** — stream encryption (KMS vs none), retention, resource
      policies, Firehose destination encryption and cross-account delivery.
- [ ] **EventBridge** — event buses, **resource policies** (cross-account `PutEvents`, wildcard
      principals), rules and targets (cross-account/cross-region targets are exfil paths),
      archives, schema registries, API destinations + connections (credentials).
- [ ] **Step Functions** — state machines, IAM role, logging level (`ALL`/`OFF`), X-Ray,
      definition (hardcoded secrets, `arn:aws:states:::aws-sdk:*` broad SDK integrations).
- [ ] **Glue** — data catalog encryption settings + catalog resource policy, connections
      (credentials, JDBC password), security configurations, jobs
      (`--enable-*` flags, script location, bookmark encryption), dev endpoints (public SSH),
      crawlers.
- [x] **Athena** — done, as the `athena` service, with two resources per region. A workgroup is the
      only place where Athena decides anything, and the query result location it fixes is a second,
      usually unnoticed, copy of the output of every query ever run under it.
      - [x] workgroups: the result configuration (output location, the bucket out of it, encryption
            option and key, expected bucket owner, bucket-owner ACL) and the Athena-managed storage
            alternative with its key; **whether the workgroup configuration is enforced** and, when
            it is not, whether a **minimum encryption** level still is; the per-query data scanned
            limit and requester-pays; the selected and effective engine version with the derived
            `engine_version_auto_upgrade`; CloudWatch query metrics and the Spark log destinations;
            the Spark execution role and the customer content key protecting the notebooks; IAM
            Identity Center and the S3 Access Grants configuration of the result reads; state,
            description, creation date and tags
      - [x] data catalogs: type (GLUE / HIVE / LAMBDA / FEDERATED) with the derived `external`,
            status and the derived `failed`, the connection type of a federated source, the error it
            reports, and the registration parameters, which Athena documents as connector function
            ARNs, a Glue catalog id or a connection ARN rather than credentials
      - [x] nine rules: query results not encrypted (excluding a workgroup on Athena-managed
            storage, which has no bucket of the account to secure), results encrypted under an S3
            managed key, workgroup configuration not enforced, a declared encryption level a client
            may silently drop, result location without an expected bucket owner, query metrics not
            published, engine version pinned, a Spark workgroup whose notebook content is encrypted
            under an AWS owned key, and a data catalog left in a failed state
      - [ ] left out: named queries and prepared statements, and the query execution history
            (`ListQueryExecutions` / `GetQueryExecution`), all of which carry SQL naming the tables
            and the literals a query was written against and grow without bound; capacity
            reservations; `ListDatabases` / `ListTableMetadata`, which would inventory what each
            catalog actually exposes at one call per catalog and per database; and the Spark
            sessions, calculations and notebook content of a Spark workgroup
      - [ ] left out: matching the result bucket to the `s3` service in preprocessing, which is what
            would turn an unencrypted result location into the finding it deserves to be — a bucket
            policy, a public access block or a lifecycle rule on the prefix holding the output of
            every query. `results_bucket` is derived and ready for it.
      - [ ] left out (rules): requester-pays and the absent per-query data scanned limit, both of
            which are cost controls with only an indirect security reading; the S3 Access Grants and
            Identity Center settings, which say how results are read back but have no insecure
            default to flag; and excluding DISABLED workgroups from the findings, since a workgroup
            is re-enabled without any of its settings changing
- [x] **SageMaker** — done, as the `sagemaker` service, with five resources per region. Every
      listing only names its resources, so each one is described.
      - [x] notebook instances: **direct internet access**, whether a subnet of the account was given
            at all (a notebook without one runs in a VPC SageMaker owns), security groups and network
            interface, root access, the minimum IMDS version, the KMS key of the ML volume, the
            execution role, the lifecycle configuration and the Git repositories cloned at start
      - [x] Studio domains: **application network access type** (`VpcOnly` vs `PublicInternetOnly`),
            VPC and subnets, who manages the application security groups, the home EFS file system
            and its key, the authentication mode, the default execution role, notebook output
            sharing, `ExecutionRoleIdentityConfig` (whether CloudTrail can name the user behind a
            call), local Docker access, and the user profiles with the execution role each one
            overrides the domain default with
      - [x] endpoints, joined with the endpoint configuration they serve, since the volume key,
            network isolation and VPC placement live there and not on the endpoint: production and
            shadow variants with their model, instance type and count or serverless configuration,
            and the data capture configuration with its destination, sampling and key
      - [x] models: network isolation, VPC configuration, execution role, inference execution mode,
            and the containers with their image, artifact, repository access mode and the **names**
            of their environment variables
      - [x] training jobs: network isolation, inter-container traffic encryption, VPC configuration,
            the output and volume KMS keys, the instance type and count (summed over heterogeneous
            instance groups), the training image, the input channels and output location, and the
            names of the hyperparameters
      - [x] seventeen rules: notebook direct internet access, notebook outside a VPC of the account,
            notebook root access, notebook without a customer managed key, notebook answering IMDSv1;
            domain with public internet access, domain without a customer managed key, domain
            allowing notebook output sharing, domain not propagating the user identity; endpoint
            without a customer managed key, endpoint capturing data without one, endpoint variant on
            a single instance; model without network isolation, model outside a VPC of the account;
            and training job without network isolation, without inter-container traffic encryption
            and outside a VPC of the account
      - [ ] left out: training jobs beyond the 200 most recent of a region, since a job record is
            kept for ever and only `DescribeTrainingJob` carries the settings a rule is about — what
            was dropped is printed rather than passed over silently; tags, which SageMaker does not
            return from any `Describe*` call and would cost one `ListTags` per resource; matching
            notebooks, endpoints, models and training jobs to their security groups, so the attack
            surface of what they can reach is not evaluated, and neither is `in_public_subnet`
            derived from their subnets; the container environment variable and hyperparameter
            *values*, which carry credentials often enough that a shareable report should not hold
            them; and the resources of Studio that are not the domain itself — spaces, apps,
            app image configs, and the lifecycle configuration scripts, whose content runs as root
      - [ ] left out (resources): batch transform jobs, processing jobs, pipelines, model packages
            and their group policies (a cross-account share), feature groups, MLflow tracking
            servers, and the account-level `DescribeSagemakerServicecatalogPortfolioStatus`
- [ ] **CI/CD chain beyond CodeBuild** — `codebuild` is collected, the rest is not, so pipelines
      with over-privileged roles and permissive GitHub OIDC trust policies go unseen.
      - [ ] CodePipeline: pipelines, service roles, source providers, cross-account actions, artifact store encryption
      - [ ] CodeCommit: repos, triggers, approval rule templates, branch protection (via approval rules)
      - [ ] CodeDeploy: applications, deployment groups, service roles
      - [ ] CodeArtifact: domains and repository policies (public/cross-account)
- [ ] **Neptune** — clusters: encryption, IAM auth, public accessibility, audit logs, deletion
      protection, backup retention.
- [ ] **DocumentDB** — `private_docdb` only; port an open-source collector (TLS, audit logs,
      encryption, deletion protection, backup retention).
- [ ] **FSx** — file systems, encryption/KMS, backups, public subnet placement, SMB/NFS exposure.
- [ ] **Storage Gateway / S3 Glacier vaults / DataSync / Transfer Family**
      - [ ] Glacier vault access policies + vault lock
      - [ ] Transfer Family servers: protocols (FTP without TLS), identity provider type, endpoint
            type (public vs VPC), logging, security policy / TLS version
- [x] **Amazon MQ** — done, as the `mq` service: brokers with their public accessibility, subnets,
      security groups, endpoints and console URLs, deployment mode, engine and whether its version
      line is still offered by the API, automatic minor version upgrade, at-rest encryption key and
      whether the account owns it, authentication strategy and LDAP settings, general and audit log
      delivery, the users of a broker with their web console access and groups, and the authorization
      map of the ActiveMQ configuration each broker currently runs, plus the region's MQ
      configurations as a separate resource.
      - [x] ten rules: public accessibility, missing ActiveMQ authorization map, audit and general
            logs, AWS owned encryption key, retired engine version, automatic minor version upgrade
            off, single-instance deployment, broker-local credentials, and a broker user holding web
            console access
      - [ ] left out: matching brokers to their security groups, so the "block unnecessary
            protocols" best practice and the attack surface of a public broker are not evaluated;
            deriving `in_public_subnet` from the broker subnets; the RabbitMQ configuration, whose
            cuttlefish properties declare the authentication backends a CONFIG_MANAGED broker uses;
            the authorization map of configurations no broker runs, since only the revision in force
            decides anything
- [ ] **AppSync** — GraphQL APIs: auth types (**API_KEY**), API keys and expiry, logging (field-level),
      WAF association, private API visibility, resolver data sources.
- [ ] **Amplify / AppFlow / Batch / WorkSpaces / Lightsail** — lower priority, but each hosts
      internet-facing or credential-bearing resources invisible today.
- [ ] **ElastiCache Serverless / MemoryDB** — `elasticache` covers clusters; serverless caches and
      MemoryDB (ACLs, TLS, encryption) are separate APIs.

## P4 — Gaps *inside* services already collected

These are cheaper than new services (facade + resource file already exist) and often close a
rule gap directly.

- [ ] **IAM — identity providers**. `resources/iam/` has users, groups, roles, policies,
      credential reports, password policy, account summary. Missing:
      - [ ] **SAML providers** (metadata, expiry) and **OIDC providers** (client IDs, thumbprints) —
            without these, federation is invisible and GitHub Actions OIDC trust policies
            (`sub` wildcard = any repo can assume the role) cannot be evaluated
      - [ ] server certificates (expiry, legacy uploads)
      - [ ] instance profiles as standalone objects (currently only reached via roles,
            `facade/iam.py:180`) — orphaned profiles are invisible
      - [ ] service-linked roles flagged as such, so they stop polluting "unused role" findings
      - [ ] `GenerateServiceLastAccessedDetails` per principal — the basis for real
            least-privilege findings rather than policy-text heuristics
      - [ ] role `MaxSessionDuration`, `PermissionsBoundary` on users and roles
      - [ ] account-level MFA / root-session settings, `GetAccountAuthorizationDetails` as a
            single-call optimisation
- [x] **Lambda** — done. On top of the functions, access policy, env variables and role that were
      already collected: **function URLs** with their auth type and CORS settings, VPC configuration
      (which also revives the security-group cross-link the report metadata was already asking for),
      the **code signing** configuration and its untrusted-artifact policy, reserved and provisioned
      concurrency, dead letter queue *and* on-failure destination, runtime management mode (whether
      AWS may patch the runtime by itself), env-var KMS key, the layers a function loads with the
      account owning each, tracing mode, ephemeral storage, architectures, package type and log
      group. **Layers** are a new resource, `awslambda.regions.id.layers`, with every published
      version and its permission policy. Thirteen rules: a function URL with `AuthType: NONE` and
      one allowing any CORS origin, a function policy and a layer version policy open to all
      principals, a layer owned by another account, code signing absent or only warning, runtime
      updates not automatic, a function off the VPC, env variables on the AWS managed key,
      asynchronous failures discarded, no reserved concurrency, and tracing not active. The
      pre-existing runtime deprecation rule is now in `default.json` as well. Package type gates the
      code signing and runtime rules, since a container image function has neither. Left out:
      **runtime EOL status still comes from the hard-coded table** in `resources/awslambda/`
      `functions.py` (no API exposes it), the layer version *contents* are not read, and event source
      mappings are not collected.
- [ ] **S3** — bucket-level and account-level Public Access Block are covered
      (`resources/s3/base.py:19`, `facade/s3.py:344`). Missing: **Object Lock** configuration,
      replication rules (cross-account/cross-region destinations), lifecycle rules,
      **Object Ownership / ACLs disabled** (`BucketOwnerEnforced`), Requester Pays,
      notification configuration, transfer acceleration, access points and multi-region access
      points (each with its own policy and PAB), directory buckets (S3 Express One Zone).
- [ ] **KMS** — `resources/kms/` has keys and grants. Missing: **key policies** as parsed
      documents (cross-account / wildcard principals), aliases, multi-region key replicas,
      custom key stores (CloudHSM/external), key origin (`EXTERNAL` / `AWS_CLOUDHSM`).
- [ ] **EC2** — missing: instance connect endpoints, dedicated hosts, capacity reservations,
      spot fleet requests, `DescribeInstanceAttribute` for `disableApiTermination` /
      `disableApiStop`, EBS snapshot cross-account share targets beyond the public/private flag,
      AMI deprecation and block-public-access-for-AMIs state.
- [ ] **VPC** — `resources/vpc/` has flow logs, NACLs, peering connections, subnets, endpoints.
      Missing: **VPC endpoint services** (who is allowed to connect, acceptance required,
      `AllowedPrincipals` with `*`), endpoint **policies** parsed for wildcards, DHCP option sets,
      DNS support/hostname flags per VPC, default VPC flagged as such, IPAM pools.
- [ ] **ECS** — cluster/service/task-definition coverage should include: task role vs execution
      role distinction, `privileged` containers, host network mode, bind-mount host paths,
      secrets passed as plain `environment` vs `secrets`, ECS Exec + its logging/KMS, container
      insights, capacity providers, public IP assignment on services.
- [ ] **EKS** — beyond the recently added rules: access entries and the access-config
      authentication mode, add-ons and their versions, Pod Identity associations, IRSA OIDC
      provider linkage, control-plane logging types actually enabled, secrets encryption
      (envelope encryption with KMS), Fargate profiles.
- [ ] **RDS** — missing: DB proxies (TLS required, IAM auth, secrets), cluster-level vs
      instance-level parameter groups' security-relevant parameters
      (`rds.force_ssl`, `log_statement`, `pgaudit`), Blue/Green deployments,
      manual snapshot cross-account share targets, Performance Insights KMS, Aurora Serverless v2,
      certificate authority / CA rotation status, engine EOL.
- [ ] **CloudFront** — distributions are collected; add origin access control (OAC) vs legacy OAI,
      geo restrictions, field-level encryption, response headers policies (HSTS/CSP),
      custom-origin protocol policy (HTTP-only to origin), logging (standard + realtime),
      **WAF association**, `KeyGroups` / signed URLs, functions and Lambda@Edge associations.
- [ ] **SNS / SQS** — resource policies are collected; ensure parsed evaluation of wildcard
      principals and missing `aws:SourceArn`/`aws:SourceAccount` conditions, plus
      SQS DLQ presence, SNS subscription protocols (unencrypted HTTP), SNS FIFO, KMS on both.
- [ ] **Secrets Manager** — add resource policies (cross-account), rotation configuration
      (enabled, interval, rotation Lambda), replica regions, KMS key (default `aws/secretsmanager`
      vs CMK), last-accessed date (unused secrets).
- [ ] **DynamoDB** — add resource-based policies, global tables / replica encryption,
      Streams configuration, TTL, export/import to S3, deletion protection.
- [ ] **ECR** — add registry-level scanning configuration and replication rules, pull-through
      cache rules, registry policy (distinct from repository policies), immutable tags per repo.
- [ ] **Account** — `resources/account/contacts.py` only. Add: primary contact information,
      account-level challenge questions presence, IAM user access to Billing console
      (`iam:AccountBillingConsoleAccess`), root MFA type (hardware vs virtual, from account summary),
      centrally managed root credentials state (already fetched at `facade/iam.py:59` — expose it).
- [ ] **Service Quotas / Trusted Advisor** — quota headroom for security-relevant limits
      (e.g. VPCs, IAM roles) and Trusted Advisor security checks (requires Business+ support).

---

## Cross-cutting items

- [ ] **Resource tags everywhere** — several collectors drop tags (e.g. `resources/vpc/*`).
      Tags are how an inventory maps resources to owners and environments; without them a
      posture report is not actionable.
- [ ] **Resource Explorer or Resource Groups Tagging API sweep** — a cheap way to enumerate
      *everything* in the account and diff it against what ScoutSuite collected, i.e. an
      automatic "coverage gap" report per scan instead of this hand-maintained file.
- [ ] **RAM (Resource Access Manager)** — resource shares, shared principals, external-share
      allowed flag. Cross-cutting because it changes the blast radius of subnets, TGWs, prefix
      lists, license configurations and Route 53 rules alike.
- [ ] **IAM permissions documentation** — every service added above needs its read-only actions
      appended to the documented scan policy, otherwise the additions fail silently in the field.
- [ ] **Region handling for global services** — new global services (Organizations, Access
      Analyzer at org level, Shield, WAF CLOUDFRONT scope) must not be fetched per region.
