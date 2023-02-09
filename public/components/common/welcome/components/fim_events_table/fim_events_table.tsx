/*
 * Wazuh app - React component building the welcome screen of an agent.
 * version, OS, registration date, last keep alive.
 *
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import React, { useState, useEffect, Fragment } from 'react';
import {
  EuiBasicTable,
  EuiFlexItem,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiToolTip,
  EuiOverlayMask,
  EuiOutsideClickDetector,
} from '@elastic/eui';
// @ts-ignore
import store from '../../../../../redux/store';
import { updateCurrentAgentData } from '../../../../../redux/actions/appStateActions';
import { getFimAlerts } from './lib';
import { formatUIDate } from '../../../../../react-services/time-service';
import { FlyoutDetail } from '../../../../agents/fim/inventory/flyout';
import { EuiLink } from '@elastic/eui';
import { getDataPlugin } from '../../../../../kibana-services';
import { translate } from '../../../util';

export function FimEventsTable({ agent, router }) {
  const openFimLabel = translate("fimEventsTable.tooltip.openFim")

  return (
    <EuiFlexItem>
      <EuiPanel paddingSize="m">
        <EuiFlexItem>
          <EuiFlexGroup>
            <EuiFlexItem>
              <EuiText size="xs">
                <h2>{translate("fimEventsTable.title")}</h2>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiToolTip position="top" content={openFimLabel}>
                <EuiButtonIcon
                  iconType="popout"
                  color="primary"
                  onClick={() => navigateToFim(agent, router)}
                  aria-label={openFimLabel}
                />
              </EuiToolTip>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="s" />
          <FimTable agent={agent} />
        </EuiFlexItem>
      </EuiPanel>
    </EuiFlexItem>
  );
}

export function useTimeFilter() {
  const { timefilter } = getDataPlugin().query.timefilter;
  const [timeFilter, setTimeFilter] = useState(timefilter.getTime());
  useEffect(() => {
    const subscription = timefilter
      .getTimeUpdate$()
      .subscribe(() => setTimeFilter(timefilter.getTime()));
    return () => {
      subscription.unsubscribe();
    };
  }, []);
  return timeFilter;
}

function FimTable({ agent }) {
  const [fimAlerts, setFimAlerts] = useState([]);
  const [isOpen, setIsOpen] = useState(false);
  const [file, setFile] = useState('');
  const [sort, setSort] = useState({ field: '_source.timestamp', direction: 'desc' });
  const timeFilter = useTimeFilter();
  useEffect(() => {
    getFimAlerts(agent.id, timeFilter, sort).then(setFimAlerts);
  }, [timeFilter, sort]);
  return (
    <Fragment>
      <EuiBasicTable
        items={fimAlerts}
        columns={columns(setFile, setIsOpen)}
        loading={false}
        sorting={{ sort }}
        onChange={(e) => setSort(e.sort)}
        itemId="fim-alerts"
        noItemsMessage={translate("fimEventsTable.message.noRecentEvents")}
      />
      {isOpen && (
        <FlyoutDetail
          agentId={agent.id}
          closeFlyout={() => setIsOpen(false)}
          fileName={file}
          view="extern"
          {...{ agent }}
        />
      )}
    </Fragment>
  );
}

function navigateToFim(agent, router) {
  window.location.href = `#/overview/?tab=fim`;
  store.dispatch(updateCurrentAgentData(agent));
  router.reload();
}

const columns = (setFile, setIsOpen) => [
  {
    field: '_source.timestamp',
    name: translate("fimEventsTable.col.time"),
    sortable: true,
    render: (field) => formatUIDate(field),
    width: '150px',
  },
  {
    field: '_source.syscheck.path',
    name: translate("fimEventsTable.col.path"),
    sortable: true,
    truncateText: true,
    render: (path) => renderPath(path, setFile, setIsOpen),
  },
  { field: '_source.syscheck.event', name: translate("fimEventsTable.col.action"), sortable: true, width: '100px' },
  {
    field: '_source.rule.description',
    name: translate("fimEventsTable.col.ruleDescription"),
    sortable: true,
    truncateText: true,
  },
  { field: '_source.rule.level', name: translate("fimEventsTable.col.ruleLevel"), sortable: true, width: '75px' },
  { field: '_source.rule.id', name: translate("fimEventsTable.col.ruleId"), sortable: true, width: '75px' },
];

const renderPath = (path, setFile, setIsOpen) => (
  <EuiLink
    className="euiTableCellContent__text euiTableCellContent--truncateText"
    onClick={() => {
      setFile(path), setIsOpen(true);
    }}
  >
    {path}
  </EuiLink>
);
