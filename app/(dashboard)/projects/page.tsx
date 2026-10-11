"use client";

import { useState } from "react";
import { FolderKanban, Loader2, Pencil, Plus, Trash2 } from "lucide-react";

import {
  useCreateProject,
  useProjects,
  type Project,
} from "@/lib/hooks/useMonitoring";
import {
  formatRelativeTime,
  describeCron,
  nextCronOccurrence,
  formatDateTime,
} from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Label, Textarea } from "@/components/ui/input";
import { EmptyState } from "@/components/dashboard/shell";
import Link from "next/link";

export default function ProjectsPage() {
  const { data, isLoading } = useProjects();
  const createProject = useCreateProject();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: "",
    primary_domain: "",
    description: "",
    scope_notes: "",
    allowed_hosts: "",
    interval_minutes: "15",
  });

  const projects = data?.projects ?? [];

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await createProject.mutateAsync({
      name: form.name,
      primary_domain: form.primary_domain || null,
      description: form.description || null,
      scope_notes: form.scope_notes || null,
      allowed_hosts: form.allowed_hosts
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
      interval_minutes: Number(form.interval_minutes) || 15,
      enabled: true,
      tags: [],
    });
    setOpen(false);
    setForm({
      name: "",
      primary_domain: "",
      description: "",
      scope_notes: "",
      allowed_hosts: "",
      interval_minutes: "15",
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Group your authorized monitoring targets by program or application.
          </p>
        </div>
        <Button size="sm" onClick={() => setOpen(true)}>
          <Plus className="h-3.5 w-3.5" />
          Add Project
        </Button>
      </div>

      {isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="skeleton h-40 rounded-xl" />
          ))}
        </div>
      ) : projects.length === 0 ? (
        <EmptyState
          icon={FolderKanban}
          title="No projects yet"
          description="Create a project to group targets by program or application, then add JavaScript URLs to monitor."
          action={
            <Button size="sm" onClick={() => setOpen(true)}>
              <Plus className="h-3.5 w-3.5" />
              Create your first project
            </Button>
          }
        />
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {projects.map((project) => (
            <ProjectCard key={project.id} project={project} />
          ))}
        </div>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add project</DialogTitle>
          </DialogHeader>
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="name">Project name</Label>
              <Input
                id="name"
                required
                value={form.name}
                onChange={(event) =>
                  setForm({ ...form, name: event.target.value })
                }
                placeholder="Acme Bug Bounty"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="domain">Primary domain</Label>
              <Input
                id="domain"
                value={form.primary_domain}
                onChange={(event) =>
                  setForm({ ...form, primary_domain: event.target.value })
                }
                placeholder="app.example.com"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="hosts">Allowed hostnames</Label>
              <Input
                id="hosts"
                value={form.allowed_hosts}
                onChange={(event) =>
                  setForm({ ...form, allowed_hosts: event.target.value })
                }
                placeholder="example.com, cdn.example.com"
              />
              <p className="text-[11px] text-[var(--muted)]">
                Comma separated. Discovery and fetching are restricted to these
                hosts. Subdomains are matched automatically.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="scope">Scope / authorization notes</Label>
              <Textarea
                id="scope"
                value={form.scope_notes}
                onChange={(event) =>
                  setForm({ ...form, scope_notes: event.target.value })
                }
                placeholder="Authorized under program X, policy dated …, in-scope hosts only."
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                value={form.description}
                onChange={(event) =>
                  setForm({ ...form, description: event.target.value })
                }
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="interval">Monitoring interval (minutes)</Label>
              <Input
                id="interval"
                type="number"
                min={1}
                max={10080}
                value={form.interval_minutes}
                onChange={(event) =>
                  setForm({ ...form, interval_minutes: event.target.value })
                }
              />
              <p className="text-[11px] text-[var(--muted)]">
                Declared preference. The actual GitHub Actions schedule is
                configured in the repository workflow.
              </p>
            </div>

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createProject.isPending}>
                {createProject.isPending && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                )}
                Save project
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ProjectCard({ project }: { project: Project }) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <Card className="transition-colors hover:border-[var(--border-strong)]">
      <CardHeader>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <CardTitle className="truncate">
              <Link href={`/assets?project=${project.id}`} className="hover:text-accent-300">
                {project.name}
              </Link>
            </CardTitle>
            <CardDescription className="truncate">
              {project.primary_domain ?? "No primary domain"}
            </CardDescription>
          </div>
          <Badge variant={project.enabled ? "ok" : "neutral"}>
            {project.enabled ? "Active" : "Paused"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {project.description && (
          <p className="line-clamp-2 text-xs text-[var(--muted)]">
            {project.description}
          </p>
        )}

        <dl className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <dt className="text-[var(--muted)]">Interval</dt>
            <dd className="mt-0.5 font-medium">{project.interval_minutes} min</dd>
          </div>
          <div>
            <dt className="text-[var(--muted)]">Next scan</dt>
            <dd className="mt-0.5 font-medium">
              {(() => {
                const next = nextCronOccurrence(
                  `*/${Math.max(1, Math.round(60 / project.interval_minutes))} * * * *`,
                );
                return next ? formatRelativeTime(next.toISOString()) : "—";
              })()}
            </dd>
          </div>
          <div>
            <dt className="text-[var(--muted)]">Allowed hosts</dt>
            <dd className="mt-0.5 truncate font-mono text-[11px]">
              {project.allowed_hosts.length
                ? project.allowed_hosts.join(", ")
                : "unrestricted"}
            </dd>
          </div>
          <div>
            <dt className="text-[var(--muted)]">Created</dt>
            <dd className="mt-0.5 font-medium">
              {formatRelativeTime(project.created_at)}
            </dd>
          </div>
        </dl>

        {project.scope_notes && (
          <p className="rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-2 text-[11px] leading-relaxed text-[var(--muted)]">
            {project.scope_notes}
          </p>
        )}

        <div className="flex items-center gap-1.5 border-t border-[var(--border)] pt-3">
          <Button asChild variant="secondary" size="sm">
            <Link href={`/assets?project=${project.id}`}>
              <Pencil className="h-3 w-3" />
              Manage targets
            </Link>
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            className="ml-auto text-bad-400"
            onClick={() => setConfirmDelete(true)}
            title="Delete project"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>

        {confirmDelete && (
          <div className="rounded-lg border border-bad-500/40 bg-bad-500/10 p-2.5 text-xs">
            <p className="text-bad-400">
              Delete this project and all of its targets, snapshots and history?
            </p>
            <div className="mt-2 flex gap-2">
              <Button
                size="sm"
                variant="destructive"
                onClick={async () => {
                  await fetch(`/api/projects?id=${project.id}`, {
                    method: "DELETE",
                  });
                  window.location.reload();
                }}
              >
                Delete permanently
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(false)}>
                Keep
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
