/*
 * Wazuh app - Simple description for each App tabs
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import { translate } from './../public/components/common/util/common/string';

export const WAZUH_MODULES = {
  general: {
    title: translate('wazuhModules.general.title', 'wazuh-general-title'),
    description: translate(
      'wazuhModules.general.description',
      'wazuh-general-description',
    ),
  },
  fim: {
    title: translate('wazuhModules.fim.title', 'wazuh-fim-title'),
    description: translate(
      'wazuhModules.fim.description',
      'wazuh-fim-description',
    ),
  },
  pm: {
    title: translate('wazuhModules.general.title', 'wazuh-general-title'),
    description: translate(
      'wazuhModules.general.description',
      'wazuh-general-description',
    ),
  },
  vuls: {
    title: translate('wazuhModules.vuls.title', 'wazuh-vuls-title'),
    description: translate(
      'wazuhModules.vuls.description',
      'wazuh-vuls-description',
    ),
  },
  oscap: {
    title: translate('wazuhModules.oscap.title', 'wazuh-oscap-title'),
    description: translate(
      'wazuhModules.oscap.description',
      'wazuh-oscap-description',
    ),
  },
  audit: {
    title: translate('wazuhModules.audit.title', 'wazuh-audit-title'),
    description: translate(
      'wazuhModules.audit.description',
      'wazuh-audit-description',
    ),
  },
  pci: {
    title: translate('wazuhModules.pci.title', 'wazuh-pci-title'),
    description: translate(
      'wazuhModules.pci.description',
      'wazuh-pci-description',
    ),
  },
  gdpr: {
    title: translate('wazuhModules.gdpr.title', 'wazuh-gdpr-title'),
    description: translate(
      'wazuhModules.gdpr.description',
      'wazuh-gdpr-description',
    ),
  },
  hipaa: {
    title: translate('wazuhModules.hipaa.title', 'wazuh-hipaa-title'),
    description: translate(
      'wazuhModules.hipaa.description',
      'wazuh-hipaa-description',
    ),
  },
  nist: {
    title: translate('wazuhModules.nist.title', 'wazuh-nist-title'),
    description: translate(
      'wazuhModules.nist.description',
      'wazuh-nist-description',
    ),
  },
  tsc: {
    title: translate('wazuhModules.tsc.title', 'wazuh-tsc-title'),
    description: translate(
      'wazuhModules.tsc.description',
      'wazuh-tsc-description',
    ),
  },
  ciscat: {
    title: translate('wazuhModules.ciscat.title', 'wazuh-ciscat-title'),
    description: translate(
      'wazuhModules.ciscat.description',
      'wazuh-ciscat-description',
    ),
  },
  aws: {
    title: translate('wazuhModules.aws.title', 'wazuh-aws-title'),
    description: translate(
      'wazuhModules.aws.description',
      'wazuh-aws-description',
    ),
  },
  office: {
    title: translate('wazuhModules.office.title', 'wazuh-office-title'),
    description: translate(
      'wazuhModules.office.description',
      'wazuh-office-description',
    ),
  },
  gcp: {
    title: translate('wazuhModules.gcp.title', 'wazuh-gcp-title'),
    description: translate(
      'wazuhModules.gcp.description',
      'wazuh-gcp-description',
    ),
  },
  virustotal: {
    title: translate('wazuhModules.virustotal.title', 'wazuh-virustotal-title'),
    description: translate(
      'wazuhModules.virustotal.description',
      'wazuh-virustotal-description',
    ),
  },
  mitre: {
    title: translate('wazuhModules.mitre.title', 'wazuh-mitre-title'),
    description: translate(
      'wazuhModules.mitre.description',
      'wazuh-mitre-description',
    ),
  },
  syscollector: {
    title: translate(
      'wazuhModules.syscollector.title',
      'wazuh-syscollector-title',
    ),
    description: translate(
      'wazuhModules.syscollector.description',
      'wazuh-syscollector-description',
    ),
  },
  stats: {
    title: translate('wazuhModules.stats.title', 'wazuh-stats-title'),
    description: translate(
      'wazuhModules.stats.description',
      'wazuh-stats-description',
    ),
  },
  configuration: {
    title: translate(
      'wazuhModules.configuration.title',
      'wazuh-configuration-title',
    ),
    description: translate(
      'wazuhModules.configuration.description',
      'wazuh-configuration-description',
    ),
  },
  osquery: {
    title: translate('wazuhModules.osquery.title', 'wazuh-osquery-title'),
    description: translate(
      'wazuhModules.osquery.description',
      'wazuh-osquery-description',
    ),
  },
  sca: {
    title: translate('wazuhModules.sca.title', 'wazuh-sca-title'),
    description: translate(
      'wazuhModules.sca.description',
      'wazuh-sca-description',
    ),
  },
  docker: {
    title: translate('wazuhModules.docker.title', 'wazuh-docker-title'),
    description: translate(
      'wazuhModules.docker.description',
      'wazuh-docker-description',
    ),
  },
  github: {
    title: translate('wazuhModules.github.title', 'wazuh-github-title'),
    description: translate(
      'wazuhModules.github.description',
      'wazuh-github-description',
    ),
  },
  devTools: {
    title: translate('wazuhModules.devTools.title', 'wazuh-devTools-title'),
    description: translate(
      'wazuhModules.devTools.description',
      'wazuh-devTools-description',
    ),
  },
  logtest: {
    title: translate('wazuhModules.logtest.title', 'wazuh-logtest-title'),
    description: translate(
      'wazuhModules.logtest.description',
      'wazuh-logtest-description',
    ),
  },
  testConfiguration: {
    title: translate(
      'wazuhModules.testConfiguration.title',
      'wazuh-testConfiguration-title',
    ),
    description: translate(
      'wazuhModules.testConfiguration.description',
      'wazuh-testConfiguration-description',
    ),
  },
};
