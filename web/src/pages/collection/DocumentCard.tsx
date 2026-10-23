import { useState } from 'react';
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  CodeBlock,
  CodeBlockCode,
  Tooltip,
} from '@patternfly/react-core';
import { CopyIcon, PencilAltIcon, TrashIcon } from '@patternfly/react-icons';
import type { Access, EJSONDocument } from '../../api/types';
import { DocumentView } from '../../components/DocumentView';
import { canDo } from '../../components/Permission';
import { summarize } from '../../lib/ejson';

interface Props {
  doc: EJSONDocument;
  id?: string;
  access?: Access;
  raw: boolean;
  onEdit?: (id: string) => void;
  onDelete?: (id: string) => void;
}

export function DocumentCard({ doc, id, access, raw, onEdit, onDelete }: Props) {
  const [copied, setCopied] = useState(false);
  const json = JSON.stringify(doc, null, 2);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  const actions = (
    <>
      <Tooltip content={copied ? 'Copied' : 'Copy Extended JSON'}>
        <Button variant="plain" aria-label="Copy document JSON" icon={<CopyIcon />} onClick={() => void copy()} />
      </Tooltip>
      {id && onEdit && canDo(access, 'update') && (
        <Button variant="plain" aria-label="Edit document" icon={<PencilAltIcon />} onClick={() => onEdit(id)} />
      )}
      {id && onDelete && canDo(access, 'remove') && (
        <Button variant="plain" aria-label="Delete document" icon={<TrashIcon />} onClick={() => onDelete(id)} isDanger />
      )}
    </>
  );
  return (
    <Card isCompact className="portal-doc">
      <CardHeader actions={{ actions, hasNoOffset: true }}>
        <CardTitle className="portal-mono">_id: {'_id' in doc ? summarize(doc._id) : '(none)'}</CardTitle>
      </CardHeader>
      <CardBody>
        {raw ? (
          <CodeBlock>
            <CodeBlockCode>{json}</CodeBlockCode>
          </CodeBlock>
        ) : (
          <DocumentView doc={doc} />
        )}
      </CardBody>
    </Card>
  );
}
