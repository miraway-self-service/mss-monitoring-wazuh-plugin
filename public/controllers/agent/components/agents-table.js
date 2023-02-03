/*
 * Wazuh app - React component for building the agents table.
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

import React, { Component, Fragment } from 'react';
import PropTypes from 'prop-types';
import {
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiToolTip,
  EuiTitle,
  EuiSpacer,
  EuiCallOut,
  EuiCheckboxGroup,
  EuiIcon,
} from '@elastic/eui';
import { getToasts } from '../../../kibana-services';
import { AppNavigate } from '../../../react-services/app-navigate';
import { GroupTruncate, translate } from '../../../components/common/util';
import { WzSearchBar, filtersToObject } from '../../../components/wz-search-bar';
import { getAgentFilterValues } from '../../../controllers/management/components/management/groups/get-agents-filters-values';
import { WzButtonPermissions } from '../../../components/common/permissions/button';
import { formatUIDate } from '../../../react-services/time-service';
import { withErrorBoundary } from '../../../components/common/hocs';
import { API_NAME_AGENT_STATUS, UI_LOGGER_LEVELS, UI_ORDER_AGENT_STATUS, AGENT_SYNCED_STATUS } from '../../../../common/constants';
import { UI_ERROR_SEVERITIES } from '../../../react-services/error-orchestrator/types';
import { getErrorOrchestrator } from '../../../react-services/common-services';
import { AgentStatus } from '../../../components/agents/agent_status';
import { AgentSynced } from '../../../components/agents/agent-synced';

export const AgentsTable = withErrorBoundary(
  class AgentsTable extends Component {
    _isMount = false;
    constructor(props) {
      super(props);
      this.state = {
        agents: [],
        isLoading: false,
        pageIndex: 0,
        pageSize: 15,
        sortDirection: 'asc',
        sortField: 'id',
        totalItems: 0,
        selectedItems: [],
        allSelected: false,
        purgeModal: false,
        isFilterColumnOpen: false,
        filters: sessionStorage.getItem('agents_preview_selected_options')
          ? JSON.parse(sessionStorage.getItem('agents_preview_selected_options'))
          : [],
      };
      this.suggestions = [
        {
          type: 'q',
          label: 'status',
          description: translate("agentsTable.suggest.status"),
          operators: ['=', '!='],
          values: UI_ORDER_AGENT_STATUS,
        },
        {
          type: 'q',
          label: 'group_config_status',
          description: translate("agentsTable.suggest.groupConfigStatus"),
          operators: ['=', '!='],
          values: [AGENT_SYNCED_STATUS.SYNCED, AGENT_SYNCED_STATUS.NOT_SYNCED],
        },
        {
          type: 'q',
          label: 'os.platform',
          description: translate("agentsTable.suggest.osPlatform"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('os.platform', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'ip',
          description: translate("agentsTable.suggest.ip"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('ip', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'name',
          description: translate("agentsTable.suggest.name"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('name', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'id',
          description: translate("agentsTable.suggest.id"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('id', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'group',
          description: translate("agentsTable.suggest.group"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('group', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'node_name',
          description: translate("agentsTable.suggest.nodeName"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('node_name', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'manager',
          description: translate("agentsTable.suggest.manager"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('manager', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'version',
          description: translate("agentsTable.suggest.version"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('version', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'configSum',
          description: translate("agentsTable.suggest.configSum"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('configSum', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'mergedSum',
          description: translate("agentsTable.suggest.mergedSum"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('mergedSum', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'dateAdd',
          description: translate("agentsTable.suggest.dateAdd"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('dateAdd', value, { q: 'id!=000' }),
        },
        {
          type: 'q',
          label: 'lastKeepAlive',
          description: translate("agentsTable.suggest.lastKeepAlive"),
          operators: ['=', '!='],
          values: async (value) => getAgentFilterValues('lastKeepAlive', value, { q: 'id!=000' }),
        },
      ];
      this.downloadCsv.bind(this);
    }

    onTableChange = ({ page = {}, sort = {} }) => {
      const { index: pageIndex, size: pageSize } = page;
      const { field: sortField, direction: sortDirection } = sort;
      this._isMount &&
        this.setState({
          pageIndex,
          pageSize,
          sortField,
          sortDirection,
        });
    };

    async componentDidMount() {
      this._isMount = true;
      await this.getItems();
    }

    componentWillUnmount() {
      this._isMount = false;
      if (sessionStorage.getItem('agents_preview_selected_options')) {
        sessionStorage.removeItem('agents_preview_selected_options');
      }
    }

    async reloadAgents() {
      await this.getItems();
      await this.props.reload();
    }

    async componentDidUpdate(prevProps, prevState) {
      if (
        !_.isEqual(prevState.filters, this.state.filters) ||
        prevState.pageIndex !== this.state.pageIndex ||
        prevState.pageSize !== this.state.pageSize ||
        prevState.sortField !== this.state.sortField ||
        prevState.sortDirection !== this.state.sortDirection
      ) {
        await this.getItems();
      } else if (
        !_.isEqual(prevProps.filters, this.props.filters) &&
        this.props.filters &&
        this.props.filters.length
      ) {
        this.setState({ filters: this.props.filters, pageIndex: 0 });
        this.props.removeFilters();
      }
    }

    async getItems() {
      try {
        this._isMount && this.setState({ isLoading: true });
        const selectFieldsList = this.defaultColumns
          .filter(field => field.field != 'actions')
          .map(field => field.field.replace('os_', 'os.')); // "os_name" subfield should be specified as 'os.name'
        const selectFields = [...selectFieldsList, 'os.uname', 'os.version'].join(','); // Add version and uname fields to render the OS icon and version in the table

        const rawAgents = await this.props.wzReq('GET', '/agents', { params: { ...this.buildFilter(), select: selectFields } });
        const formatedAgents = (((rawAgents || {}).data || {}).data || {}).affected_items.map(
          this.formatAgent.bind(this)
        );

        this._isMount &&
          this.setState({
            agents: formatedAgents,
            totalItems: (((rawAgents || {}).data || {}).data || {}).total_affected_items,
            isLoading: false,
          });
      } catch (error) {
        const options = {
          context: `${AgentsTable.name}.getItems`,
          level: UI_LOGGER_LEVELS.ERROR,
          severity: UI_ERROR_SEVERITIES.BUSINESS,
          store: true,
          error: {
            error: error,
            message: error.message || error,
            title: translate("agentsTable.error.notAgentList"),
          },
        };
        getErrorOrchestrator().handleError(options);
        this.setState({ isLoading: false });
      }
    }


    buildFilter() {
      const { pageIndex, pageSize, filters } = this.state;

      const filter = {
        ...filtersToObject(filters),
        offset: pageIndex * pageSize || 0,
        limit: pageSize,
        sort: this.buildSortFilter(),
      };
      filter.q = !filter.q ? `id!=000` : `id!=000;${filter.q}`;

      return filter;
    }

    buildSortFilter() {
      const { sortField, sortDirection } = this.state;

      const field = sortField === 'os_name' ? 'os.name,os.version' : sortField;
      const direction = sortDirection === 'asc' ? '+' : '-';

      return direction + field;
    }

    buildQFilter() {
      const { q } = this.state;
      return q === '' ? `id!=000` : `id!=000;${q}`;
    }

    formatAgent(agent) {
      const checkField = (field) => {
        return field !== undefined ? field : '-';
      };
      const agentVersion = agent.version !== undefined ? agent.version.split(' ')[1] : '-';
      const node_name = agent.node_name && agent.node_name !== 'unknown' ? agent.node_name : '-';

      return {
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
        status: agent.status,
        group_config_status: agent.group_config_status,
        group: checkField(agent.group),
        os_name: agent,
        version: agentVersion,
        node_name: node_name,
        dateAdd: agent.dateAdd ? formatUIDate(agent.dateAdd) : '-',
        lastKeepAlive: agent.lastKeepAlive ? formatUIDate(agent.lastKeepAlive) : '-',
        actions: agent,
        upgrading: false,
      };
    }

    actionButtonsRender(agent) {
      const textOpenPanel = translate("agentsTable.btn.openPanel");
      const textOpenConfigLabel = translate("agentsTable.btn.openConfig");

      return (
        <div className={'icon-box-action'}>
          <EuiToolTip content={textOpenPanel} position="left">
            <EuiButtonIcon
              onClick={(ev) => {
                ev.stopPropagation();
                this.props.clickAction(agent, 'default');
              }}
              iconType="eye"
              color={'primary'}
              aria-label={textOpenPanel}
            />
          </EuiToolTip>
          &nbsp;
          {agent.status !== API_NAME_AGENT_STATUS.NEVER_CONNECTED && (
            <EuiToolTip content={textOpenConfigLabel} position="left">
              <EuiButtonIcon
                onClick={(ev) => {
                  ev.stopPropagation();
                  this.props.clickAction(agent, 'configuration');
                }}
                color={'primary'}
                iconType="wrench"
                aria-label={textOpenConfigLabel}
              />
            </EuiToolTip>
          )}
        </div>
      );
    }

    addIconPlatformRender(agent) {
      let icon = false;
      const checkField = (field) => {
        return field !== undefined ? field : '-';
      };
      const os = (agent || {}).os;

      if (((os || {}).uname || '').includes('Linux')) {
        icon = 'linux';
      } else if ((os || {}).platform === 'windows') {
        icon = 'windows';
      } else if ((os || {}).platform === 'darwin') {
        icon = 'apple';
      }
      const os_name =
        checkField(((agent || {}).os || {}).name) +
        ' ' +
        checkField(((agent || {}).os || {}).version);

      return (
        <span className="euiTableCellContent__text euiTableCellContent--truncateText">
          <i
            className={`fa fa-${icon} AgentsTable__soBadge AgentsTable__soBadge--${icon}`}
            aria-hidden="true"
          ></i>{' '}
          {os_name === '- -' ? '-' : os_name}
        </span>
      );
    }

    reloadAgent = () => {
      this._isMount &&
        this.setState({
          isLoading: true,
        });
      this.props.reload();
    };

    downloadCsv = () => {
      const filters = this.buildFilter();
      const formatedFilters = Object.keys(filters)
        .filter((field) => !['limit', 'offset', 'sort'].includes(field))
        .map((field) => ({ name: field, value: filters[field] }));
      this.props.downloadCsv(formatedFilters);
    };

    openColumnsFilter = () => {
      this.setState({
        isFilterColumnOpen: !this.state.isFilterColumnOpen,
      });
    };

    formattedButton() {
      return (
        <>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty iconType="importAction" onClick={this.downloadCsv}>
              {translate("common.export.formated")}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiToolTip content={translate("agentsTable.tooltip.selectCol")} position="left">
              <EuiButtonEmpty onClick={this.openColumnsFilter}>
                <EuiIcon type="managementApp" color="primary" />
              </EuiButtonEmpty>
            </EuiToolTip>
          </EuiFlexItem>
        </>
      );
    }

    showToast = (color, title, text, time) => {
      getToasts().add({
        color: color,
        title: title,
        text: text,
        toastLifeTimeMs: time,
      });
    };

    callOutRender() {
      const { selectedItems, pageSize, allSelected, totalItems } = this.state;

      if (selectedItems.length === 0) {
        return;
      } else if (selectedItems.length === pageSize) {
        return (
          <div>
            <EuiSpacer size="m" />
            <EuiCallOut
              size="s"
              title={
                !allSelected ? translate("agentsTable.item.selected", {
                  selectedItemsLength: selectedItems.length
                }) : ''
              }
            >
              <EuiFlexGroup>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    onClick={() => {
                      this._isMount &&
                        this.setState((prevState) => ({
                          allSelected: !prevState.allSelected,
                        }));
                    }}
                  >
                    {translate(`agentsTable.agent.${ allSelected ? "clearAll" : "selectAll"}`, { totalItems })}
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiCallOut>
            <EuiSpacer size="s" />
          </div>
        );
      }
    }

    getTableColumnsSelected() {
      return JSON.parse(window.localStorage.getItem('columnsSelectedTableAgent')) || [];
    }

    setTableColumnsSelected(data) {
      window.localStorage.setItem('columnsSelectedTableAgent', JSON.stringify(data));
    }

    defaultColumns = [
      {
        field: 'id',
        name: 'ID',
        sortable: true,
        width: '6%',
      },
      {
        field: 'name',
        name: translate("agentsTable.col.name"),
        sortable: true,
        width: '10%',
        truncateText: true,
      },
      {
        field: 'ip',
        name: 'IP',
        width: '8%',
        truncateText: true,
        sortable: true,
      },
      {
        field: 'group',
        name: translate("agentsTable.col.group"),
        width: '14%',
        truncateText: true,
        sortable: true,
        render: (groups) => (groups !== '-' ? this.renderGroups(groups) : '-'),
      },
      {
        field: 'os_name',
        name: 'OS',
        sortable: true,
        width: '10%',
        truncateText: true,
        render: this.addIconPlatformRender,
      },
      {
        field: 'node_name',
        name: translate("agentsTable.col.nodeName"),
        width: '8%',
        truncateText: true,
        sortable: true,
      },
      {
        field: 'version',
        name: translate("agentsTable.col.version"),
        width: '5%',
        truncateText: true,
        sortable: true,
      },
      {
        field: 'dateAdd',
        name: translate("agentsTable.col.dateAdd"),
        width: '8%',
        truncateText: true,
        sortable: true,
      },
      {
        field: 'lastKeepAlive',
        name: translate("agentsTable.col.lastKeepAlive"),
        width: '8%',
        truncateText: true,
        sortable: true,
      },
      {
        field: 'status',
        name: translate("agentsTable.col.status"),
        truncateText: true,
        sortable: true,
        width: '10%',
        render: (status) => <AgentStatus status={status} labelProps={{ className: 'hide-agent-status' }} />,
      },
      {
        field: 'group_config_status',
        name:  translate("agentsTable.col.synced"),
        truncateText: true,
        sortable: true,
        width: '10%',
        render: (synced) => <AgentSynced synced={synced}/>,
      },
      {
        align: 'right',
        width: '5%',
        field: 'actions',
        name: translate("agentsTable.col.actions"),
        render: (agent) => this.actionButtonsRender(agent),
      },
    ];

    columns() {
      const selectedColumns = this.getTableColumnsSelected();

      if (selectedColumns.length != 0) {
        const newSelectedColumns = [];
        selectedColumns.forEach((item) => {
          if (item.show) {
            const column = this.defaultColumns.find((column) => column.field === item.field);
            newSelectedColumns.push(column);
          }
        });
        return newSelectedColumns;
      } else {
        const fieldColumns = this.defaultColumns.map((item) => {
          return {
            field: item.field,
            name: item.name,
            show: true,
          };
        });
        this.setTableColumnsSelected(fieldColumns);
        return this.defaultColumns;
      }
    }

    headRender() {
      const formattedButton = this.formattedButton();
      return (
        <div>
          <EuiFlexGroup>
            <EuiFlexItem>
              <EuiFlexGroup>
                <EuiFlexItem>
                  {!!this.state.totalItems && (
                    <EuiTitle size={'s'} style={{ padding: '6px 0px' }}>
                      <h2>{translate("agentsTable.label.agents")} ({this.state.totalItems})</h2>
                    </EuiTitle>
                  )}
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <WzButtonPermissions
                buttonType="empty"
                permissions={[{ action: 'agent:create', resource: '*:*:*' }]}
                iconType="plusInCircle"
                onClick={() => this.props.addingNewAgent()}
              >
                {translate("agentsTable.btn.deploy")}
              </WzButtonPermissions>
            </EuiFlexItem>
            {formattedButton}
          </EuiFlexGroup>
          <EuiSpacer size="xs" />
        </div>
      );
    }

    filterBarRender() {
      return (
        <EuiFlexGroup>
          <EuiFlexItem style={{ marginRight: 0 }}>
            <WzSearchBar
              noDeleteFiltersOnUpdateSuggests
              filters={this.state.filters}
              suggestions={this.suggestions}
              onFiltersChange={(filters) => this.setState({ filters, pageIndex: 0 })}
              placeholder={translate("agentsTable.btn.filterOrSearch")}
            />
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton iconType="refresh" fill={true} onClick={() => this.reloadAgents()}>
              {translate('common.refresh')}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      );
    }

    selectColumnsRender() {
      const columnsSelected = this.getTableColumnsSelected();

      const onChange = (optionId) => {
        let item = columnsSelected.find((item) => item.field === optionId);
        item.show = !item.show;
        this.setTableColumnsSelected(columnsSelected);
        this.forceUpdate();
      };

      const options = () => {
        return columnsSelected.map((item) => {
          return {
            id: item.field,
            label: item.name,
            checked: item.show,
          };
        });
      };

      return this.state.isFilterColumnOpen ? (
        <EuiFlexGroup>
          <EuiFlexItem>
            <EuiCheckboxGroup
              options={options()}
              onChange={onChange}
              className="columnsSelectedCheckboxs"
              idToSelectedMap={{}}
            />
          </EuiFlexItem>
        </EuiFlexGroup>
      ) : (
        ''
      );
    }

    tableRender() {
      const getRowProps = (item) => {
        const { id } = item;
        return {
          'data-test-subj': `row-${id}`,
          className: 'customRowClass',
          onClick: () => {},
        };
      };

      const getCellProps = (item, column) => {
        if (column.field == 'actions') {
          return;
        }
        return {
          onMouseDown: (ev) => {
            AppNavigate.navigateToModule(ev, 'agents', { tab: 'welcome', agent: item.id });
            ev.stopPropagation();
          },
        };
      };

      const {
        pageIndex,
        pageSize,
        totalItems,
        agents,
        sortField,
        sortDirection,
        isLoading,
      } = this.state;
      const columns = this.columns();
      const pagination =
        totalItems > 15
          ? {
              pageIndex: pageIndex,
              pageSize: pageSize,
              totalItemCount: totalItems,
              pageSizeOptions: [15, 25, 50, 100],
            }
          : false;
      const sorting = {
        sort: {
          field: sortField,
          direction: sortDirection,
        },
      };

      return (
        <EuiFlexGroup>
          <EuiFlexItem>
            <EuiBasicTable
              items={agents}
              itemId="id"
              columns={columns}
              onChange={this.onTableChange}
              sorting={sorting}
              loading={isLoading}
              rowProps={getRowProps}
              cellProps={getCellProps}
              noItemsMessage={translate("agentsTable.message.noAgent")}
              {...(pagination && { pagination })}
            />
          </EuiFlexItem>
        </EuiFlexGroup>
      );
    }

    filterGroupBadge = (group) => {
      const { filters } = this.state;
      let auxFilters = filters.map((filter) => filter.value.match(/group=(.*S?)/)[1]);
      if (filters.length > 0) {
        !auxFilters.includes(group)
          ? this.setState({
              filters: [...filters, { field: 'q', value: `group=${group}` }],
            })
          : false;
      } else {
        this.setState({
          filters: [...filters, { field: 'q', value: `group=${group}` }],
        });
      }
    };

    renderGroups(groups) {
      return (
        <GroupTruncate
          groups={groups}
          length={25}
          label={'more'}
          action={'filter'}
          filterAction={this.filterGroupBadge}
          {...this.props}
        />
      );
    }

    render() {
      const title = this.headRender();
      const filter = this.filterBarRender();
      const selectColumnsRender = this.selectColumnsRender();
      const table = this.tableRender();
      const callOut = this.callOutRender();
      let renderPurgeModal, loadItems;

      return (
        <div>
          {filter}
          <EuiSpacer size="m" />
          <EuiPanel paddingSize="m">
            {title}
            {loadItems}
            {callOut}
            {selectColumnsRender}
            {table}
            {renderPurgeModal}
          </EuiPanel>
        </div>
      );
    }
  }
);

AgentsTable.propTypes = {
  wzReq: PropTypes.func,
  addingNewAgent: PropTypes.func,
  downloadCsv: PropTypes.func,
  clickAction: PropTypes.func,
  timeService: PropTypes.func,
  reload: PropTypes.func,
};
