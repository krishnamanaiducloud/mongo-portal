import { useState, type ReactNode } from 'react';
import {
  Alert,
  Button,
  Content,
  Form,
  FormGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  TextInput,
} from '@patternfly/react-core';
import { errorMessage } from '../api/client';

interface ConfirmProps {
  title: string;
  body: ReactNode;
  /** When set, the user must type this exact text to enable the action. */
  typeToConfirm?: string;
  confirmLabel: string;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}

/** Confirmation dialog for destructive operations. */
export function ConfirmDialog({ title, body, typeToConfirm, confirmLabel, onConfirm, onClose }: ConfirmProps) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const ready = !typeToConfirm || typed === typeToConfirm;

  const run = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal variant={ModalVariant.small} isOpen onClose={onClose} aria-labelledby="confirm-title">
      <ModalHeader title={title} labelId="confirm-title" titleIconVariant="danger" />
      <ModalBody>
        <Content component="p">{body}</Content>
        {typeToConfirm && (
          <Form onSubmit={(e) => { e.preventDefault(); if (ready) void run(); }}>
            <FormGroup label={`Type "${typeToConfirm}" to confirm`} fieldId="confirm-input">
              <TextInput id="confirm-input" value={typed} onChange={(_e, v) => setTyped(v)} autoComplete="off" autoFocus />
            </FormGroup>
          </Form>
        )}
        {error && <Alert variant="danger" isInline title={error} className="pf-v6-u-mt-md" />}
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" onClick={() => void run()} isDisabled={!ready || busy} isLoading={busy}>
          {confirmLabel}
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
