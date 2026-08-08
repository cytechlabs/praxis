import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../../context/AuthContext';
import MainLayout from '@/components/MainLayout';
import { fetchCredentials } from '@/services/systemService';
import { PageHeader, SearchInput, Card, CardHeader, CardBody, EmptyState, SkeletonTable, Button } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import Pagination from '@/components/Pagination';
import { Key, Lock, Server, ExternalLink, Plus } from 'lucide-react';
import Link from 'next/link';
import Head from 'next/head';

interface Credential {
  id: number;
  name: string;
  auth_method: string;
  username?: string;
  vault_path?: string;
  systems?: System[];
}

interface System {
  id: number;
  hostname: string;
  ip_address: string;
}

const AllCredentialsPage: React.FC = () => {
  const { user, canWrite } = useAuth();
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;

  useEffect(() => {
    const loadCredentials = async () => {
      if (!user) return;

      try {
        setLoading(true);
        setError(null);
        const data = await fetchCredentials();
        setCredentials(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load credentials');
        console.error('Error loading credentials:', err);
      } finally {
        setLoading(false);
      }
    };

    loadCredentials();
  }, [user]);

  const getCredentialTypeIcon = (authMethod: string) => {
    if (authMethod === 'ssh_key') {
      return <Key size={18} className="text-green-400" />;
    } else {
      return <Lock size={18} className="text-yellow-400" />;
    }
  };

  const getCredentialTypeLabel = (credential: Credential) => {
    return credential.auth_method === 'ssh_key' ? 'SSH Key' : 'Password';
  };

  const filteredCredentials = useMemo(() => {
    if (!search.trim()) return credentials;
    const q = search.toLowerCase();
    return credentials.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        (c.username && c.username.toLowerCase().includes(q)) ||
        c.auth_method.toLowerCase().includes(q)
    );
  }, [credentials, search]);

  useEffect(() => { setPageOffset(0); }, [search]);

  const paginatedCredentials = filteredCredentials.slice(pageOffset, pageOffset + pageLimit);

  return (
    <MainLayout>
        <Head>
          <title>All Credentials | Praxis</title>
        </Head>
        <PageHeader
          title="Credential Management"
          actions={
            <div className="flex items-center gap-2">
              {canWrite && (
                <Link href="/credentials/add">
                  <Button variant="primary" icon={<Plus size={16} />}>
                    Add Credential
                  </Button>
                </Link>
              )}
              <HelpLink slug="credentials-and-vault" />
            </div>
          }
        />

        {error && (
          <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded">
            {error}
          </div>
        )}

        <Card>
          <CardHeader
            action={
              <div className="w-72">
                <SearchInput
                  placeholder="Search credentials..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            }
          >
            All Credentials
          </CardHeader>
          <CardBody className="p-0">
            {loading ? (
              <SkeletonTable rows={5} cols={5} />
            ) : filteredCredentials.length === 0 ? (
              <EmptyState
                icon={<Key size={24} className="text-content-subtle" />}
                title={search ? 'No credentials match your search' : 'No credentials found'}
                description={!search ? 'Get started by adding your first credential.' : undefined}
                action={
                  !search ? (
                    <Link href="/credentials/add">
                      <Button variant="primary" icon={<Plus size={16} />}>
                        Add Your First Credential
                      </Button>
                    </Link>
                  ) : undefined
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-border">
                  <thead>
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content-muted uppercase tracking-wider">
                        Name
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content-muted uppercase tracking-wider">
                        Type
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content-muted uppercase tracking-wider">
                        Details
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content-muted uppercase tracking-wider">
                        Systems
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content-muted uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {paginatedCredentials.map((credential) => (
                      <tr key={credential.id} className="hover:bg-white/[0.03]/50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {getCredentialTypeIcon(credential.auth_method)}
                            <span className="ml-2 text-content">{credential.name}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="px-2 py-1 text-xs rounded-full bg-surface-overlay text-content">
                            {getCredentialTypeLabel(credential)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {credential.username ? (
                            <div className="text-content">
                              <span className="text-content-muted">Username:</span> {credential.username}
                            </div>
                          ) : (
                            <span className="text-content-subtle">-</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {credential.systems && credential.systems.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {credential.systems.map((system) => (
                                <Link
                                  key={system.id}
                                  href={`/system-management/system/${system.id}`}
                                  className="inline-flex items-center px-2 py-1 text-xs bg-border text-content rounded hover:bg-border-strong"
                                >
                                  <Server size={12} className="mr-1" />
                                  {system.hostname}
                                </Link>
                              ))}
                            </div>
                          ) : (
                            <span className="text-content-subtle">No systems</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex space-x-2">
                            <Link
                              href={`/credentials/edit/${credential.id}`}
                              className="text-content hover:text-content"
                              title="Edit Credential"
                            >
                              Edit
                            </Link>
                            {credential.vault_path && (
                              <Link
                                href={`/system-management/vault-management?path=${encodeURIComponent(credential.vault_path)}`}
                                className="text-green-500 hover:text-green-400 flex items-center"
                                title="View in Vault"
                              >
                                <ExternalLink size={14} className="mr-1" />
                                Vault
                              </Link>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {filteredCredentials.length > pageLimit && (
              <Pagination
                offset={pageOffset}
                limit={pageLimit}
                total={filteredCredentials.length}
                onPageChange={setPageOffset}
              />
            )}
          </CardBody>
        </Card>
    </MainLayout>
  );
};

export default AllCredentialsPage;
