import React, { useState } from 'react';
import {
  EuiPanel,
  EuiSpacer,
  EuiAccordion,
  EuiButtonGroup,
  htmlIdGenerator,
} from '@elastic/eui';
import { osButtons } from '../wazuh-config';
import { translate } from '../../../components/common/util/common/string';

export const PrincipalButtonGroup = ({
  legend,
  options,
  idSelected,
  onChange,
}) => {
  return (
    <>
      <EuiButtonGroup
        color='primary'
        legend={legend}
        options={options}
        idSelected={idSelected}
        onChange={onChange}
      />
      <EuiSpacer size='l' />
      <WzAccordion>
        <EuiButtonGroup
          color='primary'
          legend={legend}
          options={osButtons}
          idSelected={idSelected}
          onChange={onChange}
        />
      </WzAccordion>
    </>
  );
};

export const WzAccordion = ({ children }) => {
  const [isAccordionOpen, setIsAccordionOpen] = useState(false);
  const rightArrowAccordionId = htmlIdGenerator('wz-accordion')();
  const toggleLabel = translate(`wzAccordion.${isAccordionOpen ? 'open' : 'hide'}`)
  return (
    <EuiAccordion
      id={rightArrowAccordionId}
      arrowDisplay='left'
      buttonContent={toggleLabel}
      onToggle={(isOpen: boolean) => setIsAccordionOpen(isOpen)}
      className={'action-btn-td'}
    >
      <EuiSpacer size='l' />
      <EuiPanel className={'wz-border-none'} color='transparent'>
        {children}
      </EuiPanel>
    </EuiAccordion>
  );
};
