import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import {
  AlertTriangle,
  ArrowUp,
  Download,
  File as FileIcon,
  FolderPlus,
  Folder as FolderIcon,
  HardDrive,
  Home,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader, ConfirmModal, Input, Modal, LoadingState } from '@/components/ui';
import {
  DirEntry,
  downloadUrl,
  listDir,
  mkdirPath,
  unlinkPath,
  uploadFile,
} from '../../services/fileTransferService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface Props {
  systemId: number;
  systemHostname?: string;
}

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const fmtMode = (mode: number) => {
  // Render the lower 9 bits as rwxrwxrwx.
  const parts = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'];
  let out = '';
  for (let i = 0; i < 9; i++) {
    out += mode & (1 << (8 - i)) ? parts[i] : '-';
  }
  return out;
};

const parent = (path: string): string => {
  if (!path || path === '/') return '/';
  const trimmed = path.replace(/\/+$/, '');
  const idx = trimmed.lastIndexOf('/');
  if (idx <= 0) return '/';
  return trimmed.slice(0, idx);
};

const join = (base: string, name: string): string => {
  if (base.endsWith('/')) return base + name;
  return `${base}/${name}`;
};

const FileTransferPanel = ({ systemId, systemHostname }: Props) => {
  const formatTimestamp = useFormatTimestamp();
  const [path, setPath] = useState<string>('/');
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  const [showMkdir, setShowMkdir] = useState(false);
  const [newDir, setNewDir] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const load = useCallback(async (p: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await listDir(systemId, p);
      setPath(res.path);
      setEntries(res.entries);
    } catch {
      // PRA-274: operator copy, never the raw exception text. The panel's Refresh
      // button is the retry affordance.
      setError('Couldn’t list files on this host. Retry, or check that it’s reachable.');
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [systemId]);

  useEffect(() => { load('/'); }, [load]);

  const handleEntryClick = (e: DirEntry) => {
    if (e.is_dir) load(join(path, e.name));
  };

  const handleDownload = (e: DirEntry) => {
    // Let the browser handle auth (cookie) and streaming via a direct GET.
    window.open(downloadUrl(systemId, join(path, e.name)), '_blank');
  };

  const handleUpload = async (file: File) => {
    setUploading(true);
    try {
      await uploadFile(systemId, join(path, file.name), file);
      toast.success(`Uploaded ${file.name}`);
      await load(path);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleMkdir = async () => {
    const name = newDir.trim();
    if (!name || name.includes('/')) {
      toast.error('Folder name cannot contain /');
      return;
    }
    try {
      await mkdirPath(systemId, join(path, name));
      toast.success('Folder created');
      setShowMkdir(false);
      setNewDir('');
      await load(path);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'mkdir failed');
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await unlinkPath(systemId, deleteTarget);
      toast.success('Deleted');
      await load(path);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setDeleteTarget(null);
    }
  };

  return (
    <Card className="mt-4">
      <CardHeader
        action={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => load(path)} disabled={loading}>
              <RefreshCw size={14} className="mr-1" /> Refresh
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setShowMkdir(true)} disabled={loading}>
              <FolderPlus size={14} className="mr-1" /> New folder
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => fileInputRef.current?.click()}
              disabled={loading || uploading}
              loading={uploading}
            >
              <Upload size={14} className="mr-1" /> Upload
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              hidden
              onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
            />
          </div>
        }
      >
        <div>
          <div className="flex items-center gap-2">
            <HardDrive size={14} /> Files
            {systemHostname && <span className="text-xs font-normal text-content-subtle">· {systemHostname}</span>}
          </div>
          <div className="text-xs font-normal text-content-subtle mt-0.5">
            SFTP browser. Remote permissions are enforced by the host kernel - you can only see what your
            mapped Linux account is allowed to.
          </div>
        </div>
      </CardHeader>
      <CardBody>
        {/* Breadcrumbs */}
        <div className="mb-3 flex items-center gap-1 text-sm">
          <button onClick={() => load('/')} className="p-1 rounded hover:bg-white/5 text-content-muted hover:text-content">
            <Home size={14} />
          </button>
          {path !== '/' && (
            <button onClick={() => load(parent(path))} className="p-1 rounded hover:bg-white/5 text-content-muted hover:text-content" aria-label="Up one level">
              <ArrowUp size={14} />
            </button>
          )}
          <span className="text-xs text-content-subtle ml-2 font-mono break-all">{path}</span>
        </div>

        {error && (
          <div className="mb-3 p-3 rounded-md bg-red-900/30 border border-red-700 text-red-200 text-xs flex gap-2">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            <div>{error}</div>
          </div>
        )}

        {loading ? (
          <LoadingState label="Loading files" />
        ) : entries.length === 0 ? (
          <div className="text-content-subtle text-sm py-4 text-center">
            {error ? 'Nothing to show.' : '(empty directory)'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">Size</th>
                  <th className="py-2 pr-4">Mode</th>
                  <th className="py-2 pr-4">Modified</th>
                  <th className="py-2 pr-4 text-right" />
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.name} className="border-b border-border hover:bg-white/5">
                    <td className="py-2 pr-4">
                      <button
                        onClick={() => handleEntryClick(e)}
                        className={`flex items-center gap-2 ${e.is_dir ? 'text-content hover:text-white' : 'text-content-muted'}`}
                      >
                        {e.is_dir
                          ? <FolderIcon size={14} className="text-yellow-500" />
                          : <FileIcon size={14} className="text-content-subtle" />}
                        <span className="font-mono">{e.name}{e.is_dir ? '/' : ''}</span>
                        {e.is_link && <Badge variant="neutral">link</Badge>}
                      </button>
                    </td>
                    <td className="py-2 pr-4 text-content-muted tabular-nums">{e.is_dir ? '-' : fmtBytes(e.size)}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-content-subtle">{fmtMode(e.mode)}</td>
                    <td className="py-2 pr-4 text-xs text-content-subtle">
                      {e.mtime ? formatTimestamp(new Date(e.mtime * 1000)) : '-'}
                    </td>
                    <td className="py-2 pr-4 text-right">
                      {/* PRA-270: quiet shared icon actions; delete stays neutral
                          here and gets its Signal-Red danger treatment in the
                          confirmation dialog below. */}
                      <div className="flex gap-1 justify-end">
                        {!e.is_dir && (
                          <Button
                            variant="ghost"
                            size="sm"
                            iconOnly
                            icon={<Download size={14} />}
                            aria-label={`Download ${e.name}`}
                            title="Download"
                            onClick={() => handleDownload(e)}
                          />
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          iconOnly
                          icon={<Trash2 size={14} />}
                          aria-label={`Delete ${e.name}`}
                          title="Delete"
                          onClick={() => setDeleteTarget(join(path, e.name))}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>

      <Modal open={showMkdir} onClose={() => { setShowMkdir(false); setNewDir(''); }} title="New folder" maxWidth="max-w-md">
        <div className="space-y-3">
          <p className="text-sm text-content">Create a folder in <span className="font-mono text-content-muted">{path}</span>.</p>
          <Input value={newDir} onChange={(e) => setNewDir(e.target.value)} placeholder="folder-name" />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => { setShowMkdir(false); setNewDir(''); }}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleMkdir} disabled={!newDir.trim()}>Create</Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete"
        message={`Delete ${deleteTarget}? Directories must be empty.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Card>
  );
};

export default FileTransferPanel;
