import { FormGroup, FormHelperText, HelperText, HelperTextItem, TextArea } from '@patternfly/react-core';
import { normalizeInput } from '../lib/ejson';

interface Props {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  want?: 'object' | 'array';
  rows?: number;
  placeholder?: string;
  hint?: string;
  required?: boolean;
}

/** Text area for Extended JSON / mongo-shell style input with inline validation. */
export function JsonField({ id, label, value, onChange, want = 'object', rows = 3, placeholder, hint, required }: Props) {
  const { error } = normalizeInput(value, want);
  const empty = !value.trim();
  return (
    <FormGroup label={label} fieldId={id} isRequired={required}>
      <TextArea
        id={id}
        value={value}
        onChange={(_e, v) => onChange(v)}
        rows={rows}
        resizeOrientation="vertical"
        className="portal-mono"
        placeholder={placeholder}
        validated={!empty && error ? 'error' : 'default'}
        spellCheck={false}
        autoComplete="off"
      />
      <FormHelperText>
        <HelperText>
          {!empty && error ? (
            <HelperTextItem variant="error">{error}</HelperTextItem>
          ) : (
            <HelperTextItem>{hint ?? 'Extended JSON. Shell helpers such as ObjectId("…") and ISODate("…") are accepted.'}</HelperTextItem>
          )}
        </HelperText>
      </FormHelperText>
    </FormGroup>
  );
}

/** Returns normalized Extended JSON or throws a validation error message. */
export function toExtJSON(value: string, want: 'object' | 'array' = 'object'): string {
  const r = normalizeInput(value, want);
  if (r.error) throw new Error(r.error);
  return r.value;
}
