/*
 * Wazuh app - Agents visualizations
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import { translate } from "../common/util/common/string";

const getAgentVisTrans = (key) => translate(`agentVisualizations.${key}`);

export const agentVisualizations = {
  general: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: getAgentVisTrans("general.alertEvolution"),
            id: 'Wazuh-App-Agents-General-Alert-groups-evolution',
            width: 50
          },
          { title: getAgentVisTrans("general.alerts"), id: 'Wazuh-App-Agents-General-Alerts', width: 50 }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("general.top5Alerts"),
            id: 'Wazuh-App-Agents-General-Top-5-alerts',
            width: 33
          },
          {
            title: getAgentVisTrans("general.top5RuleGroup"),
            id: 'Wazuh-App-Agents-General-Top-10-groups',
            width: 33
          },
          {
            title: getAgentVisTrans("general.top5Pci"),
            id: 'Wazuh-App-Agents-General-Top-5-PCI-DSS-Requirements',
            width: 34
          }
        ]
      },
    ]
  },
  aws: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: getAgentVisTrans("aws.sources"),
            id: 'Wazuh-App-Agents-AWS-Top-sources',
            width: 25
          },
          {
            title: getAgentVisTrans("aws.accounts"),
            id: 'Wazuh-App-Agents-AWS-Top-accounts',
            width: 25
          },
          {
            title: getAgentVisTrans("aws.s3Buckets"),
            id: 'Wazuh-App-Agents-AWS-Top-buckets',
            width: 25
          },
          {
            title: getAgentVisTrans("aws.regions"),
            id: 'Wazuh-App-Agents-AWS-Top-regions',
            width: 25
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("aws.eventsBySource"),
            id: 'Wazuh-App-Agents-AWS-Events-by-source',
            width: 50
          },
          {
            title: getAgentVisTrans("aws.eventsByS3Buckets"),
            id: 'Wazuh-App-Agents-AWS-Events-by-s3-bucket',
            width: 50
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: getAgentVisTrans("aws.geolocationMap"),
            id: 'Wazuh-App-Agents-AWS-geo'
          }
        ]
      },
    ]
  },
  fim: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("fim.mostActiveUser"),
            id: 'Wazuh-App-Agents-FIM-Users',
            width: 25
          },
          {
            title: getAgentVisTrans("fim.actions"),
            id: 'Wazuh-App-Agents-FIM-Actions',
            width: 25
          },
          {
            title: getAgentVisTrans("fim.events"),
            id: 'Wazuh-App-Agents-FIM-Events',
            width: 50
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: getAgentVisTrans("fim.filesAdded"),
            id: 'Wazuh-App-Agents-FIM-Files-added',
            width: 33
          },
          {
            title: getAgentVisTrans("fim.filesModified"),
            id: 'Wazuh-App-Agents-FIM-Files-modified',
            width: 33
          },
          {
            title: getAgentVisTrans("fim.filesDeleted"),
            id: 'Wazuh-App-Agents-FIM-Files-deleted',
            width: 34
          }
        ]
      },
    ]
  },
  gcp: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("gcp.top5Rules"),
            id: 'Wazuh-App-Agents-GCP-Top-5-rules',
            width: 50
          },
          {
            title: getAgentVisTrans("gcp.topQueryEvents"),
            id: 'Wazuh-App-Agents-GCP-Event-Query-Name',
            width: 25
          },
          {
            title: getAgentVisTrans("gcp.top5Instances"),
            id: 'Wazuh-App-Agents-GCP-Top-5-instances',
            width: 25
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("gcp.topProject"),
            id: 'Wazuh-App-Agents-GCP-Top-ProjectId-By-SourceType',
            width: 25
          },
          {
            title: getAgentVisTrans("gcp.alertsEvolution"),
            id: 'Wazuh-App-Agents-GCP-Events-Over-Time',
            width: 75
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("gcp.auth"),
            id: 'Wazuh-App-Agents-GCP-authAnswer-Bar',
            width: 40
          },
          {
            title:getAgentVisTrans("gcp.resource"),
            id: 'Wazuh-App-Agents-GCP-Top-ResourceType-By-Project-Id',
            width: 60
          },
        ]
      },
    ]
  },
  pci: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("general.top5RuleGroup"),
            id: 'Wazuh-App-Agents-PCI-Groups',
            width: 33
          },
          {
            title: getAgentVisTrans("gcp.top5Rules"),
            id: 'Wazuh-App-Agents-PCI-Rule',
            width: 33
          },
          {
            title: getAgentVisTrans("general.top5Pci"),
            id: 'Wazuh-App-Agents-PCI-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("pci.requirement"),
            id: 'Wazuh-App-Agents-PCI-Requirements',
            width: 75
          },
          {
            title: getAgentVisTrans('pci.ruleLevelDistribution'),
            id: 'Wazuh-App-Agents-PCI-Rule-level-distribution',
            width: 25
          }
        ]
      },
    ]
  },
  gdpr: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("general.top5RuleGroup"),
            id: 'Wazuh-App-Agents-GDPR-Groups',
            width: 33
          },
          {
            title: getAgentVisTrans("gcp.top5Rules"),
            id: 'Wazuh-App-Agents-GDPR-Rule',
            width: 33
          },
          {
            title: getAgentVisTrans("gdpr.top5Requirement"),
            id: 'Wazuh-App-Agents-GDPR-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("gdpr.requirement"),
            id: 'Wazuh-App-Agents-GDPR-Requirements',
            width: 75
          },
          {
            title: getAgentVisTrans("pci.ruleLevelDistribution"),
            id: 'Wazuh-App-Agents-GDPR-Rule-level-distribution',
            width: 25
          }
        ]
      },
    ]
  },
  nist: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: translate("wazuhModules.stats.title"),
            id: 'Wazuh-App-Agents-NIST-Stats',
            width: 25
          },
          {
            title: getAgentVisTrans("nist.top10Requirement"),
            id: 'Wazuh-App-Agents-NIST-top-10-requirements',
            width: 25
          },
          {
            title: getAgentVisTrans("nist.requirementsDistributedByLevel"),
            id: 'Wazuh-App-Agents-NIST-Requirement-by-level',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("nist.requirementsOverTime"),
            id: 'Wazuh-App-Agents-NIST-Requirements-stacked-overtime'
          }
        ]
      },
    ]
  },
  tsc: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("general.top5RuleGroup"),
            id: 'Wazuh-App-Agents-TSC-Groups',
            width: 33
          },
          {
            title: getAgentVisTrans("gcp.top5Rules"),
            id: 'Wazuh-App-Agents-TSC-Rule',
            width: 33
          },
          {
            title: getAgentVisTrans("tsc.top5requirements"),
            id: 'Wazuh-App-Agents-TSC-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("tsc.requirements"),
            id: 'Wazuh-App-Agents-TSC-Requirements',
            width: 75
          },
          {
            title: getAgentVisTrans("pci.ruleLevelDistribution"),
            id: 'Wazuh-App-Agents-TSC-Rule-level-distribution',
            width: 25
          }
        ]
      },
    ]
  },
  hipaa: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("nist.requirementsOverTime"),
            id: 'Wazuh-App-Agents-HIPAA-Requirements-Stacked-Overtime',
            width: 50
          },
          {
            title: getAgentVisTrans("nist.top10Requirement"),
            id: 'Wazuh-App-Agents-HIPAA-top-10',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("hipaa.requirements"),
            id: 'Wazuh-App-Agents-HIPAA-Burbles',
            width: 50
          },
          {
            title: getAgentVisTrans('hipaa.requirementsDistributionByLevel'),
            id: 'Wazuh-App-Agents-HIPAA-Distributed-By-Level',
            width: 25
          },
          {
            title: getAgentVisTrans("hipaa.mostCommonAlerts"),
            id: 'Wazuh-App-Agents-HIPAA-Most-Common',
            width: 25
          }
        ]
      },
    ]
  },
  virustotal: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: getAgentVisTrans("virustotal.lastScanned"),
            id: 'Wazuh-App-Agents-Virustotal-Last-Files-Pie',
            width: 25
          },
          {
            title: getAgentVisTrans("virustotal.malicious"),
            id: 'Wazuh-App-Agents-Virustotal-Malicious-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: getAgentVisTrans("virustotal.lastFiles"),
            id: 'Wazuh-App-Agents-Virustotal-Files-Table'
          }
        ]
      },
    ]
  },
  osquery: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("osquery.mostCommonActions"),
            id: 'Wazuh-App-Agents-Osquery-most-common-osquery-actions',
            width: 25
          },
          {
            title: getAgentVisTrans("osquery.evolution"),
            id: 'Wazuh-App-Agents-Osquery-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("osquery.mostCommonPacks"),
            id: 'Wazuh-App-Agents-Osquery-top-5-packs-being-used',
            width: 25
          },
          {
            title: getAgentVisTrans("osquery.mostCommonRule"),
            id: 'Wazuh-App-Agents-Osquery-monst-common-rules-being-fired',
            width: 75
          }
        ]
      },
    ]
  },
  mitre: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: getAgentVisTrans("mitre.alertsEvolution"),
            id: 'Wazuh-App-Agents-MITRE-Alerts-Evolution',
            width: 70
          },
          {
            title: getAgentVisTrans("mitre.topTactics"),
            id: 'Wazuh-App-Agents-MITRE-Top-Tactics',
            width: 30
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: getAgentVisTrans("mitre.ruleLevelByAttack"),
            id: 'Wazuh-App-Agents-MITRE-Level-By-Attack',
            width: 33
          },
          {
            title: getAgentVisTrans("mitre.attacksByTactic"),
            id: 'Wazuh-App-Agents-MITRE-Attacks-By-Tactic',
            width: 34
          },
          {
            title: getAgentVisTrans("mitre.ruleLevelByTactic"),
            id: 'Wazuh-App-Agents-MITRE-Level-By-Tactic',
            width: 34
          }
        ]
      },
    ]
  },
  docker: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("docker.top5Image"),
            id: 'Wazuh-App-Agents-Docker-top-5-images',
            width: 25
          },
          {
            title: getAgentVisTrans("docker.top5Events"),
            id: 'Wazuh-App-Agents-Docker-top-5-actions',
            width: 25
          },
          {
            title: getAgentVisTrans("docker.resourcesUsageOverTime"),
            id: 'Wazuh-App-Agents-Docker-Types-over-time',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: getAgentVisTrans("docker.eventsOccurredEvolution"),
            id: 'Wazuh-App-Agents-Docker-Actions-over-time'
          }
        ]
      },
    ]
  },
  oscap: {
    rows: [
      {
        height: 230,
        vis: [
          {
            title: getAgentVisTrans("oscap.top5Scans"),
            id: 'Wazuh-App-Agents-OSCAP-Scans',
            width: 25
          },
          {
            title: getAgentVisTrans("oscap.top5Profiles"),
            id: 'Wazuh-App-Agents-OSCAP-Profiles',
            width: 25
          },
          {
            title: getAgentVisTrans("oscap.top5Content"),
            id: 'Wazuh-App-Agents-OSCAP-Content',
            width: 25
          },
          {
            title: getAgentVisTrans("oscap.top5Severity"),
            id: 'Wazuh-App-Agents-OSCAP-Severity',
            width: 25
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: getAgentVisTrans("oscap.dailySAcansEvolution"),
            id: 'Wazuh-App-Agents-OSCAP-Daily-scans-evolution'
          }
        ]
      },
      {
        height: 250,
        vis: [
          {
            title: getAgentVisTrans("oscap.alertsTop5"),
            id: 'Wazuh-App-Agents-OSCAP-Top-5-Alerts',
            width: 50
          },
          {
            title: getAgentVisTrans("oscap.alertsHighRisk"),
            id: 'Wazuh-App-Agents-OSCAP-Top-5-High-risk-alerts',
            width: 50
          }
        ]
      },
    ]
  },
  ciscat: {
    rows: [
      {
        height: 320,
        vis: [
          {
            title: getAgentVisTrans("ciscat.top5Groups"),
            id: 'Wazuh-app-Agents-CISCAT-top-5-groups',
            width: 60
          },
          {
            title: getAgentVisTrans("ciscat.scanEvolution"),
            id: 'Wazuh-app-Agents-CISCAT-scan-result-evolution',
            width: 40
          }
        ]
      },
    ]
  },
  pm: {
    rows: [
      {
        height: 290,
        vis: [
          {
            title: getAgentVisTrans(".pm.alertsOT"),
            id: 'Wazuh-App-Agents-PM-Events-over-time',
            width: 50
          },
          {
            title: getAgentVisTrans("pm.ruleDistribution"),
            id: 'Wazuh-App-Agents-PM-Top-5-rules',
            width: 50
          }
        ]
      },
      {
        height: 240,
        vis: [
          {
            title: getAgentVisTrans("pm.eventsPerControTypeEvolution"),
            id: 'Wazuh-App-Agents-PM-Events-per-agent-evolution'
          }
        ]
      },
    ]
  },
  audit: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: getAgentVisTrans("pm.groups"),
            id: 'Wazuh-App-Agents-Audit-Groups',
            width: 33
          },
          {
            title: getAgentVisTrans("pm.commands"),
            id: 'Wazuh-App-Agents-Audit-Commands',
            width: 33
          },
          {
            title: getAgentVisTrans("pm.files"),
            id: 'Wazuh-App-Agents-Audit-Files',
            width: 34
          }
        ]
      },
      {
        height: 310,
        vis: [
          {
            title: getAgentVisTrans("pm.alertsOT"),
            id: 'Wazuh-App-Agents-Audit-Alerts-over-time'
          }
        ]
      },
    ]
  },
  github: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: getAgentVisTrans("github.alertsEvolutionByOrganization"),
            id: 'Wazuh-App-Agents-GitHub-Alerts-Evolution-By-Organization',
            width: 60
          },
          {
            title: getAgentVisTrans("github.top5Organizations"),
            id: 'Wazuh-App-Agents-GitHub-Top-5-Organizations-By-Alerts',
            width: 40
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: getAgentVisTrans("github.topAlerts"),
            id: 'Wazuh-App-Agents-GitHub-Alert-Action-Type-By-Organization',
            width: 40
          },
          {
            title: getAgentVisTrans("github.moreAlertUser"),
            id: 'Wazuh-App-Agents-GitHub-Users-With-More-Alerts',
            width: 60
          }
        ]
      },
    ]
  },
};
