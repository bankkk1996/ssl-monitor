import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { CircleAlert, CircleCheck, CircleX, Globe, Hourglass, Loader2, Lock, Plus, RefreshCw, ShieldCheck, Trash2, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { api, ApiError, type Domain, type Priority, type Status } from '@/api';
import { cn } from '@/lib/utils';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ThemeToggle } from '@/components/theme-toggle';

const DAY = 86_400_000;
const dateFmt = new Intl.DateTimeFormat('th-TH', { day: 'numeric', month: 'short', year: 'numeric' });
const timeFmt = new Intl.DateTimeFormat('th-TH', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const PRIORITY_LABEL: Record<Priority, string> = { High: 'สำคัญมาก', Normal: 'ปกติ', Low: 'ต่ำ' };
const PRIORITY_RANK: Record<Priority, number> = { High: 0, Normal: 1, Low: 2 };
const SSL_ERRORS: Record<string, string> = {
  CERT_HAS_EXPIRED: 'ใบรับรองหมดอายุ',
  ERR_TLS_CERT_ALTNAME_INVALID: 'ชื่อโดเมนไม่ตรงกับใบรับรอง',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'ใบรับรองแบบ self-signed',
  SELF_SIGNED_CERT_IN_CHAIN: 'มีใบรับรอง self-signed ใน chain',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'chain ใบรับรองไม่ครบ',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'chain ใบรับรองไม่ครบ',
  CERT_NOT_YET_VALID: 'ใบรับรองยังไม่เริ่มใช้งาน',
  CERT_REVOKED: 'ใบรับรองถูกเพิกถอน',
};

const daysLeft = (iso: string | null) => (iso ? Math.floor((Date.parse(iso) - Date.now()) / DAY) : null);
const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้');

type Level = 'good' | 'warning' | 'critical' | 'pending';
const LEVEL_STYLE: Record<Level, string> = {
  good: 'bg-good-soft text-good',
  warning: 'bg-warning-soft text-warning',
  critical: 'bg-critical-soft text-critical',
  pending: 'bg-muted text-muted-foreground',
};
const LEVEL_ICON: Record<Level, ReactNode> = {
  good: <CircleCheck />, warning: <TriangleAlert />, critical: <CircleAlert />, pending: <Hourglass />,
};

// Status always shows an icon and text, never colour alone.
function StatusBadge({ level, children, className }: { level: Level; children: ReactNode; className?: string }) {
  return (
    <Badge variant="outline" className={cn('border-transparent font-semibold tabular-nums', LEVEL_STYLE[level], className)}>
      {LEVEL_ICON[level]}
      {children}
    </Badge>
  );
}

function ExpiryBadge({ days, warnAt, critAt, broken = false }: { days: number | null; warnAt: number; critAt: number; broken?: boolean }) {
  if (days === null) return <StatusBadge level="pending">รอเช็ก</StatusBadge>;
  const level: Level = broken || days <= critAt ? 'critical' : days <= warnAt ? 'warning' : 'good';
  return <StatusBadge level={level}>{days < 0 ? `หมดแล้ว ${-days} วัน` : `${days} วัน`}</StatusBadge>;
}

function UpBadge({ d }: { d: Domain }) {
  if (d.is_alive === null) return <StatusBadge level="pending">รอเช็ก</StatusBadge>;
  if (d.is_alive) return <StatusBadge level="good">ใช้งานได้</StatusBadge>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span><StatusBadge level="critical">เข้าไม่ได้</StatusBadge></span>
      </TooltipTrigger>
      <TooltipContent>{d.last_error}</TooltipContent>
    </Tooltip>
  );
}

function SslCell({ d }: { d: Domain }) {
  const days = daysLeft(d.ssl_valid_to);
  return (
    <div className="flex flex-col items-start gap-1">
      <ExpiryBadge days={days} warnAt={14} critAt={7} broken={Boolean(d.ssl_error)} />
      {d.ssl_error ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span><StatusBadge level="critical" className="whitespace-normal text-left">{SSL_ERRORS[d.ssl_error] ?? d.ssl_error}</StatusBadge></span>
          </TooltipTrigger>
          <TooltipContent>{d.ssl_error}</TooltipContent>
        </Tooltip>
      ) : (
        <span className="text-xs text-muted-foreground">
          {d.ssl_valid_to ? `${dateFmt.format(new Date(d.ssl_valid_to))}${d.ssl_issuer ? ` · ${d.ssl_issuer}` : ''}` : 'เช็กภายใน 30 นาที'}
        </span>
      )}
    </div>
  );
}

function DomainCell({ d }: { d: Domain }) {
  const days = daysLeft(d.domain_valid_to);
  return (
    <div className="flex flex-col items-start gap-1">
      <ExpiryBadge days={days} warnAt={60} critAt={14} />
      <span className="text-xs text-muted-foreground">
        {d.domain_valid_to
          ? `${dateFmt.format(new Date(d.domain_valid_to))}${d.registered_domain && d.registered_domain !== d.domain ? ` · ${d.registered_domain}` : ''}`
          : d.domain_error ?? ''}
      </span>
    </div>
  );
}

function RowActions({ d, onRefresh, onDelete }: { d: Domain; onRefresh: (d: Domain) => Promise<void>; onDelete: (d: Domain) => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex justify-end gap-1">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon" disabled={busy} aria-label={`เช็ก ${d.domain} อีกครั้ง`}
            onClick={async () => { setBusy(true); await onRefresh(d); setBusy(false); }}>
            <RefreshCw className={cn(busy && 'animate-spin')} />
          </Button>
        </TooltipTrigger>
        <TooltipContent>เช็กเว็บและโดเมนอีกครั้ง</TooltipContent>
      </Tooltip>
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`ลบ ${d.domain}`} className="hover:text-destructive"><Trash2 /></Button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>เลิกติดตาม {d.domain}?</AlertDialogTitle>
            <AlertDialogDescription>ข้อมูลการเช็กของโดเมนนี้จะถูกลบ และจะไม่มีการแจ้งเตือนอีก</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>ยกเลิก</AlertDialogCancel>
            <AlertDialogAction className="bg-destructive text-white hover:bg-destructive/90" onClick={() => onDelete(d)}>ลบ</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function urgency(d: Domain): (number | string)[] {
  const s = daysLeft(d.ssl_valid_to) ?? 9999;
  const r = daysLeft(d.domain_valid_to) ?? 9999;
  return [d.is_alive === 0 ? 0 : 1, d.ssl_error ? 0 : 1, Math.min(s, r), PRIORITY_RANK[d.priority], d.domain];
}
function compare(a: Domain, b: Domain) {
  const x = urgency(a), y = urgency(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

function StatCard({ label, value, icon }: { label: string; value: number | string; icon: ReactNode }) {
  return (
    <Card className="gap-1 py-4">
      <CardHeader className="flex flex-row items-center justify-between px-4">
        <CardDescription>{label}</CardDescription>
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
      </CardHeader>
      <CardContent className="px-4 text-2xl font-bold tabular-nums">{value}</CardContent>
    </Card>
  );
}

export default function App() {
  const [domains, setDomains] = useState<Domain[] | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [email, setEmail] = useState('');
  const [fatal, setFatal] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState('');
  const [priority, setPriority] = useState<Priority>('Normal');
  const [adding, setAdding] = useState(false);
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    const [list, st] = await Promise.all([api.list(), api.status()]);
    setDomains(list);
    setStatus(st);
  }, []);

  useEffect(() => {
    api.me()
      .then((me) => { setEmail(me.email); return load(); })
      .catch((e) => setFatal(errMsg(e)));
  }, [load]);

  const sorted = useMemo(() => [...(domains ?? [])].sort(compare), [domains]);
  const stats = useMemo(() => {
    const list = domains ?? [];
    return {
      total: list.length,
      down: list.filter((d) => d.is_alive === 0).length,
      ssl: list.filter((d) => d.ssl_error || ((daysLeft(d.ssl_valid_to) ?? 999) <= 14)).length,
      reg: list.filter((d) => (daysLeft(d.domain_valid_to) ?? 999) <= 60).length,
    };
  }, [domains]);

  const health = useMemo(() => {
    const problems: string[] = [];
    if (!status || !domains?.length) return problems;
    if (status.lastSslCheck) {
      const hours = (Date.now() - Date.parse(status.lastSslCheck)) / 3_600_000;
      if (hours > 2) problems.push(`ตัวเช็ก SSL ไม่ได้รันมา ${Math.floor(hours)} ชั่วโมง (ล่าสุด ${timeFmt.format(new Date(status.lastSslCheck))})`);
    }
    if (status.dispatch && !status.dispatch.ok) problems.push(`สั่งรันตัวเช็กบน GitHub ไม่สำเร็จ: ${status.dispatch.error} — token อาจหมดอายุ`);
    return problems;
  }, [status, domains]);

  async function add(e: FormEvent) {
    e.preventDefault();
    setAdding(true);
    try {
      const row = await api.add(newDomain, priority);
      setDomains((list) => [...(list ?? []), row]);
      setNewDomain('');
      toast.success(`เพิ่ม ${row.domain} แล้ว`);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setAdding(false);
    }
  }

  async function refresh(d: Domain) {
    try {
      const row = await api.refresh(d.id);
      setDomains((list) => list?.map((x) => (x.id === row.id ? row : x)) ?? null);
    } catch (err) {
      toast.error(errMsg(err));
    }
  }

  async function remove(d: Domain) {
    try {
      await api.remove(d.id);
      setDomains((list) => list?.filter((x) => x.id !== d.id) ?? null);
      toast.success(`เลิกติดตาม ${d.domain} แล้ว`);
    } catch (err) {
      toast.error(errMsg(err));
    }
  }

  return (
    <div className="mx-auto flex min-h-svh max-w-5xl flex-col gap-6 px-4 py-6 sm:px-6">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldCheck className="size-5" /></div>
          <div>
            <h1 className="text-xl font-semibold leading-tight">SSL Monitor</h1>
            <p className="text-sm text-muted-foreground">ใบรับรอง SSL · สถานะเว็บ · วันหมดอายุโดเมน</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="h-9" disabled={reloading || !domains}
            onClick={async () => { setReloading(true); try { await load(); } catch (e) { toast.error(errMsg(e)); } setReloading(false); }}>
            <RefreshCw className={cn(reloading && 'animate-spin')} /><span className="hidden sm:inline">รีเฟรช</span>
          </Button>
          <ThemeToggle />
        </div>
      </header>

      {fatal && (
        <Alert variant="destructive"><CircleX /><AlertTitle>ใช้งานไม่ได้</AlertTitle><AlertDescription>{fatal}</AlertDescription></Alert>
      )}
      {health.length > 0 && (
        <Alert className="border-warning/50 bg-warning-soft text-warning">
          <TriangleAlert />
          <AlertTitle>ตัวเช็กอัตโนมัติมีปัญหา</AlertTitle>
          <AlertDescription className="text-warning">{health.map((p) => <p key={p}>{p}</p>)}</AlertDescription>
        </Alert>
      )}

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="สรุป">
        <StatCard label="ทั้งหมด" value={domains ? stats.total : '–'} icon={<Globe />} />
        <StatCard label="เข้าไม่ได้" value={domains ? stats.down : '–'} icon={<CircleX />} />
        <StatCard label="SSL มีปัญหา / ≤ 14 วัน" value={domains ? stats.ssl : '–'} icon={<Lock />} />
        <StatCard label="โดเมน ≤ 60 วัน" value={domains ? stats.reg : '–'} icon={<Hourglass />} />
      </section>

      <Card>
        <CardHeader>
          <CardTitle>เพิ่มโดเมน</CardTitle>
          <CardDescription>เพิ่มแล้วจะเช็กว่าเว็บเปิดได้และวันหมดอายุโดเมนทันที ส่วนใบรับรอง SSL เช็กทุก 30 นาที</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={add} className="flex flex-col gap-2 sm:flex-row">
            <Input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com"
              inputMode="url" autoComplete="off" required aria-label="โดเมน" className="sm:flex-1" />
            <Select value={priority} onValueChange={(v) => setPriority(v as Priority)}>
              <SelectTrigger className="sm:w-36" aria-label="ความสำคัญ"><SelectValue /></SelectTrigger>
              <SelectContent>
                {(['High', 'Normal', 'Low'] as Priority[]).map((p) => <SelectItem key={p} value={p}>{PRIORITY_LABEL[p]}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button type="submit" disabled={adding || !!fatal}>
              {adding ? <Loader2 className="animate-spin" /> : <Plus />}
              {adding ? 'กำลังเช็ก…' : 'เพิ่ม'}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card className="py-0">
        {!domains ? (
          <CardContent className="py-10 text-center text-muted-foreground">{fatal ? '' : 'กำลังโหลด…'}</CardContent>
        ) : !domains.length ? (
          <CardContent className="py-10 text-center text-muted-foreground">ยังไม่มีโดเมน — เพิ่มโดเมนแรกจากช่องด้านบน</CardContent>
        ) : (
          <>
            {/* desktop: table */}
            <Table className="hidden md:table">
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-6">โดเมน</TableHead>
                  <TableHead>ใบรับรอง SSL</TableHead>
                  <TableHead>ทะเบียนโดเมน</TableHead>
                  <TableHead className="pr-6"><span className="sr-only">จัดการ</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="pl-6 align-top whitespace-normal">
                      <div className="flex flex-col items-start gap-1">
                        <span className="flex items-center gap-2">
                          <a href={`https://${d.domain}`} target="_blank" rel="noopener noreferrer" className="font-medium hover:underline">{d.domain}</a>
                          {d.priority !== 'Normal' && <Badge variant="secondary">{PRIORITY_LABEL[d.priority]}</Badge>}
                        </span>
                        <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <UpBadge d={d} />
                          {d.ssl_checked_at && `เช็กล่าสุด ${timeFmt.format(new Date(d.ssl_checked_at))}`}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal"><SslCell d={d} /></TableCell>
                    <TableCell className="align-top whitespace-normal"><DomainCell d={d} /></TableCell>
                    <TableCell className="pr-6 align-top"><RowActions d={d} onRefresh={refresh} onDelete={remove} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {/* mobile: stacked list */}
            <ul className="divide-y md:hidden">
              {sorted.map((d) => (
                <li key={d.id} className="flex flex-col gap-3 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex min-w-0 flex-col items-start gap-1">
                      <a href={`https://${d.domain}`} target="_blank" rel="noopener noreferrer" className="font-medium break-all hover:underline">{d.domain}</a>
                      <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <UpBadge d={d} />
                        {d.priority !== 'Normal' && <Badge variant="secondary">{PRIORITY_LABEL[d.priority]}</Badge>}
                      </span>
                    </div>
                    <RowActions d={d} onRefresh={refresh} onDelete={remove} />
                  </div>
                  <div className="grid grid-cols-[auto_1fr] items-start gap-x-3 gap-y-2 text-sm">
                    <span className="pt-0.5 text-muted-foreground">SSL</span><SslCell d={d} />
                    <span className="pt-0.5 text-muted-foreground">โดเมน</span><DomainCell d={d} />
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <footer className="mt-auto text-center text-xs text-muted-foreground">{email && `เข้าสู่ระบบเป็น ${email}`}</footer>
    </div>
  );
}
