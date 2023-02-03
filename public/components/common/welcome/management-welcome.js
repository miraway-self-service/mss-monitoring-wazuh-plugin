/*
 * Wazuh app - React component for building the management welcome screen.
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
import React, { Component } from 'react';
import {
  EuiCard,
  EuiIcon,
  EuiPanel,
  EuiFlexItem,
  EuiFlexGroup,
  EuiSpacer,
  EuiPage
} from '@elastic/eui';
import { updateGlobalBreadcrumb } from '../../../redux/actions/globalBreadcrumbActions';
import store from '../../../redux/store';

import { updateManagementSection } from '../../../redux/actions/managementActions';
import WzReduxProvider from '../../../redux/wz-redux-provider';
import { connect } from 'react-redux';
import { translate } from '../util';

class ManagementWelcome extends Component {
  constructor(props) {
    super(props);

    this.state = {};
  }

  setGlobalBreadcrumb() {
    const breadcrumb = [{ text: '' }, { text: 'Management' }];
    store.dispatch(updateGlobalBreadcrumb(breadcrumb));
  }

  async componentDidMount() {
    this.setGlobalBreadcrumb();
  }

  switchSection(section) {
    this.props.switchTab(section, true);
    this.props.updateManagementSection(section);
  }

  render() {
    return (
      <WzReduxProvider>
        <EuiPage className="wz-welcome-page">
          <EuiFlexGroup>
            <EuiFlexItem>
              <EuiCard title description betaBadgeLabel={translate('managementWelcome.betaBadgeLabel.administration')}>
                <EuiSpacer size="m" />
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="indexRollupApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.rules.title')}
                      onClick={() => this.switchSection('rules')}
                      description={translate('managementWelcome.rules.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="indexRollupApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.decoders.title')}
                      onClick={() => this.switchSection('decoders')}
                      description={translate('managementWelcome.decoders.description')}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="indexRollupApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.CDBLists.title')}
                      onClick={() => this.switchSection('lists')}
                      description={translate('managementWelcome.CDBLists.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="usersRolesApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.groups.title')}
                      onClick={() => this.switchSection('groups')}
                      description={translate('managementWelcome.groups.description')}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon size="xl" type="devToolsApp" color="primary" />
                      }
                      title={translate('managementWelcome.configuration.title')}
                      onClick={() => this.switchSection('configuration')}
                      description={translate('managementWelcome.configuration.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem />
                </EuiFlexGroup>
              </EuiCard>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiCard title description betaBadgeLabel={translate('managementWelcome.betaBadgeLabel.statusAndReports')}>
                <EuiSpacer size="m" />
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon size="xl" type="uptimeApp" color="primary" />
                      }
                      title={translate('managementWelcome.status.title')}
                      onClick={() => this.switchSection('status')}
                      description={translate('managementWelcome.status.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="indexPatternApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.cluster.title')}
                      onClick={() => this.switchSection('monitoring')}
                      description={translate('managementWelcome.cluster.description')}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon size="xl" type="filebeatApp" color="primary"/>
                      }
                      title={translate('managementWelcome.logs.title')}
                      onClick={() => this.switchSection('logs')}
                      description={translate('managementWelcome.logs.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon
                          size="xl"
                          type="reportingApp"
                          color="primary"
                        />
                      }
                      title={translate('managementWelcome.reporting.title')}
                      onClick={() => this.switchSection('reporting')}
                      description={translate('managementWelcome.reporting.description')}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
                <EuiFlexGroup>
                  <EuiFlexItem>
                    <EuiCard
                      layout="horizontal"
                      className="homSynopsis__card"
                      icon={
                        <EuiIcon size="xl" type="visualizeApp" color="primary" />
                      }
                      title={translate('managementWelcome.statistics.title')}
                      onClick={() => this.switchSection('statistics')}
                      description={translate('managementWelcome.statistics.description')}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem>
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiCard>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPage>
      </WzReduxProvider>
    );
  }
}


const mapDispatchToProps = dispatch => {
  return {
    updateManagementSection: section =>
      dispatch(updateManagementSection(section))
  };
};

export default connect(
  null,
  mapDispatchToProps
)(ManagementWelcome);
