import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Spinner,
} from '@patternfly/react-core';
import { errorMessage } from '../../api/client';
import { fetchDocument, useInsertDocument, useReplaceDocument } from '../../api/hooks';
import { JsonField, toExtJSON } from '../../components/JsonField';

interface Props {
  db: string;
  coll: string;
  /** Document id token; undefined to insert a new document. */
  id?: string;
  onClose: () => void;
}

export function DocumentEditor({ db, coll, id, onClose }: Props) {
  const [text, setText] = useState(id ? '' : '{\n  \n}');
  const [loading, setLoading] = useState(!!id);
  const [loadError, setLoadError] = useState<unknown>();
  const [saveError, setSaveError] = useState<string>();
  const insert = useInsertDocument(db, coll);
  const replace = useReplaceDocument(db, coll);
  const busy = insert.isPending || replace.isPending;

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetchDocument(db, coll, id, 'relaxed')
      .then((r) => {
        if (!cancelled) setText(JSON.stringify(r.document, null, 2));
      })
      .catch((e: unknown) => {
        if (!cancelled) setLoadError(e);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [db, coll, id]);

  const save = async () => {
    setSaveError(undefined);
    let document: string;
    try {
      document = toExtJSON(text);
    } catch (e) {
      setSaveError(errorMessage(e));
      return;
    }
    try {
      if (id) await replace.mutateAsync({ id, document });
      else await insert.mutateAsync(document);
      onClose();
    } catch (e) {
      setSaveError(errorMessage(e));
    }
  };

  return (
    <Modal variant={ModalVariant.large} isOpen onClose={onClose} aria-labelledby="doc-editor-title">
      <ModalHeader
        title={id ? 'Edit document' : 'Insert document'}
        labelId="doc-editor-title"
        description={`${db}.${coll} — relaxed Extended JSON. The _id field cannot be changed.`}
      />
      <ModalBody>
        {loading && <Spinner aria-label="Loading document" />}
        {loadError ? <Alert variant="danger" isInline title={errorMessage(loadError)} /> : null}
        {!loading && !loadError && (
          <JsonField id="doc-editor" label="Document" value={text} onChange={setText} rows={20} required
            hint='Use {"$oid": "…"}, {"$date": "…"}, {"$numberDecimal": "…"} or shell helpers for BSON types.' />
        )}
        {saveError && <Alert variant="danger" isInline title={saveError} className="pf-v6-u-mt-md" />}
      </ModalBody>
      <ModalFooter>
        <Button onClick={() => void save()} isDisabled={loading || !!loadError || busy} isLoading={busy}>
          {id ? 'Save changes' : 'Insert'}
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
