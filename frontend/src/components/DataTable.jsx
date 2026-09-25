import React from 'react';
import { EmptyState } from './ui.jsx';

export default function DataTable({ columns, rows, rowKey, onRowClick, emptyTitle, emptyBody }) {
  const [sort, setSort] = React.useState(null); // {key, dir}

  const sorted = React.useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    const get = col && col.sortValue ? col.sortValue : (r) => r[sort.key];
    return [...rows].sort((a, b) => {
      const va = get(a); const vb = get(b);
      if (va == null) return 1; if (vb == null) return -1;
      if (typeof va === 'number' && typeof vb === 'number') return sort.dir === 'asc' ? va - vb : vb - va;
      return sort.dir === 'asc'
        ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
  }, [rows, sort, columns]);

  if (!rows || rows.length === 0) {
    return <div className="ts-table-wrap"><EmptyState title={emptyTitle || 'No results'} body={emptyBody} /></div>;
  }

  return (
    <div className="ts-table-wrap">
      <table className="ts-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.sortable === false ? '' : 'sortable'}
                onClick={c.sortable === false ? undefined : () =>
                  setSort((s) => s && s.key === c.key && s.dir === 'desc' ? { key: c.key, dir: 'asc' } : { key: c.key, dir: 'desc' })}>
                {c.label}{sort && sort.key === c.key ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={rowKey(r)} className={onRowClick ? 'clickable' : ''}
              onClick={onRowClick ? () => onRowClick(r) : undefined}>
              {columns.map((c) => <td key={c.key}>{c.render ? c.render(r) : r[c.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pager({ page, pages, total, onPage }) {
  if (!pages || pages <= 1) return null;
  return (
    <div className="ts-pager">
      <span>{total} results</span>
      <button className="ts-btn small" disabled={page <= 0} onClick={() => onPage(page - 1)}>Previous</button>
      <span>Page {page + 1} of {pages}</span>
      <button className="ts-btn small" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}
