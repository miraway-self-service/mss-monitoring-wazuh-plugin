/*
 * Wazuh app - Build all sections for MenuAgent.
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import { WAZUH_MODULES_ID } from '../../../../../common/constants';
import { translate } from '../../util/common/string';

const getMenuTrans = (label: string): string => translate(`agentsSection.menuAgent.${label}`);

export const getAgentSections = (menuAgent: any) => {
  return {
    securityInformation: {
      id: 'securityInformation',
      text: getMenuTrans("securityInformation"),
      isTitle: true,
    },
    auditing: {
      id: 'auditing',
      text: getMenuTrans("auditing"),
      isTitle: true,
    },
    threatDetection: {
      id: 'threatDetection',
      text: getMenuTrans("threatDetection"),
      isTitle: true,
    },
    regulatoryCompliance: {
      id: 'regulatoryCompliance',
      text: getMenuTrans("regulatoryCompliance"),
      isTitle: true,
    },
    general: {
      id: WAZUH_MODULES_ID.SECURITY_EVENTS,
      text: getMenuTrans("general"),
      isPin: menuAgent.general ? menuAgent.general : false,
    },
    fim: {
      id: WAZUH_MODULES_ID.INTEGRITY_MONITORING,
      text: getMenuTrans("fim"),
      isPin: menuAgent.fim ? menuAgent.fim : false,
    },
    aws: {
      id: WAZUH_MODULES_ID.AMAZON_WEB_SERVICES,
      text: getMenuTrans("aws"),
      isPin: menuAgent.aws ? menuAgent.aws : false,
    },
    gcp: {
      id: WAZUH_MODULES_ID.GOOGLE_CLOUD_PLATFORM,
      text: getMenuTrans("gcp"),
      isPin: menuAgent.gcp ? menuAgent.gcp : false,
    },
    github: {
      id: WAZUH_MODULES_ID.GITHUB,
      text: getMenuTrans("github"),
      isPin: menuAgent.github ? menuAgent.github : false
    },
    pm: {
      id: WAZUH_MODULES_ID.POLICY_MONITORING,
      text: getMenuTrans("pm"),
      isPin: menuAgent.pm ? menuAgent.pm : false,
    },
    sca: {
      id: WAZUH_MODULES_ID.SECURITY_CONFIGURATION_ASSESSMENT,
      text: getMenuTrans("sca"),
      isPin: menuAgent.sca ? menuAgent.sca : false,
    },
    audit: {
      id: WAZUH_MODULES_ID.AUDITING,
      text: getMenuTrans("audit"),
      isPin: menuAgent.audit ? menuAgent.audit : false,
    },
    oscap: {
      id: WAZUH_MODULES_ID.OPEN_SCAP,
      text: getMenuTrans("oscap"),
      isPin: menuAgent.oscap ? menuAgent.oscap : false,
    },
    ciscat: {
      id: WAZUH_MODULES_ID.CIS_CAT,
      text: getMenuTrans("ciscat"),
      isPin: menuAgent.oscap ? menuAgent.oscap : false,
    },
    vuls: {
      id: WAZUH_MODULES_ID.VULNERABILITIES,
      text: getMenuTrans("vuls"),
      isPin: menuAgent.vuls ? menuAgent.vuls : false,
    },
    virustotal: {
      id: WAZUH_MODULES_ID.VIRUSTOTAL,
      text: getMenuTrans("virustotal"),
      isPin: menuAgent.virustotal ? menuAgent.virustotal : false,
    },
    osquery: {
      id: WAZUH_MODULES_ID.OSQUERY,
      text: getMenuTrans("osquery"),
      isPin: menuAgent.osquery ? menuAgent.osquery : false,
    },
    docker: {
      id: WAZUH_MODULES_ID.DOCKER,
      text: getMenuTrans("docker"),
      isPin: menuAgent.docker ? menuAgent.docker : false,
    },
    mitre: {
      id: WAZUH_MODULES_ID.MITRE_ATTACK,
      text: getMenuTrans("mitre"),
      isPin: menuAgent.mitre ? menuAgent.mitre : false,
    },
    pci: {
      id: WAZUH_MODULES_ID.PCI_DSS,
      text: getMenuTrans("pci"),
      isPin: menuAgent.pci ? menuAgent.pci : false,
    },
    gdpr: {
      id: WAZUH_MODULES_ID.GDPR,
      text: getMenuTrans("gdpr"),
      isPin: menuAgent.gdpr ? menuAgent.gdpr : false,
    },
    hipaa: {
      id: WAZUH_MODULES_ID.HIPAA,
      text: getMenuTrans("hipaa"),
      isPin: menuAgent.hipaa ? menuAgent.hipaa : false,
    },
    nist: {
      id: WAZUH_MODULES_ID.NIST_800_53,
      text: getMenuTrans("nist"),
      isPin: menuAgent.nist ? menuAgent.nist : false,
    },
    tsc: { 
      id: WAZUH_MODULES_ID.TSC, 
      text: getMenuTrans("tsc"), 
      isPin: menuAgent.tsc ? menuAgent.tsc : false 
    },
  };
};
