---
name: onevalue-frontend
description: Frontend development for OneValue Delivery Intelligence Console using Lovable, React, and Tahoe OS26 design system. Use when implementing UI components, dashboards, Google OAuth, real-time Supabase integration, or data visualization. Covers component architecture, design standards, authentication, and user experience patterns.
# corpus-label: benign
# corpus-source: github-scrape
# corpus-repo: nithinvaradaraj-crypto/OneValue-Console
# corpus-url: https://github.com/nithinvaradaraj-crypto/OneValue-Console/blob/a7cef9aab6671e7eb2fea7df8e231f1dae6a6f90/onevalue-frontend-SKILL.md
# corpus-round: 2026-03-19
---

# OneValue Frontend Developer Skill

## Role & Responsibilities

You are the Frontend Lead Developer for the OneValue Delivery Intelligence Console. Your mission is to build an "extremely intrusive" yet beautiful dashboard interface that ensures critical delivery information is never missed.

## Technical Stack

- **Framework:** React 18+ with TypeScript
- **Platform:** Lovable (React-based with built-in Supabase)
- **Styling:** Tailwind CSS + Custom Tahoe OS26 theme
- **State Management:** React Query + Zustand
- **Auth:** Google OAuth 2.0 with allowlist
- **Real-time:** Supabase subscriptions
- **Charts:** Recharts for data visualization

## Tahoe OS26 Design System

### Design Philosophy

Tahoe OS26 is inspired by Apple's design language with these core principles:

1. **Liquid Glass Surfaces** - Semi-transparent overlays with blur effects
2. **Rounded Geometry** - Smooth corners everywhere (12-16px border radius)
3. **Subtle Depth** - Layered elevation with soft shadows
4. **Intrusive Alerts** - Critical information demands attention
5. **Premium Feel** - High-quality typography and spacing

### Color Palette

```javascript
// tailwind.config.js
export default {
  theme: {
    extend: {
      colors: {
        // Primary - Blue tones
        primary: {
          50: '#EFF6FF',
          100: '#DBEAFE',
          500: '#3B82F6',
          600: '#2563EB',
          700: '#1D4ED8',
        },
        // Health status
        health: {
          healthy: '#10B981',    // Green
          risk: '#F59E0B',       // Amber
          critical: '#EF4444',   // Red
          unknown: '#6B7280',    // Gray
        },
        // Glass surfaces
        glass: {
          light: 'rgba(255, 255, 255, 0.1)',
          medium: 'rgba(255, 255, 255, 0.2)',
          dark: 'rgba(0, 0, 0, 0.3)',
        }
      },
      backdropBlur: {
        xs: '2px',
        sm: '4px',
        DEFAULT: '8px',
        md: '12px',
        lg: '16px',
        xl: '24px',
      },
      borderRadius: {
        'tahoe': '12px',
        'tahoe-lg': '16px',
        'tahoe-xl': '20px',
      }
    }
  }
}
```

### Component Design Patterns

#### Glass Card Component

```typescript
// src/components/ui/GlassCard.tsx
import { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  intensity?: 'light' | 'medium' | 'strong';
  elevated?: boolean;
}

export function GlassCard({ 
  children, 
  className, 
  intensity = 'medium',
  elevated = false 
}: GlassCardProps) {
  const blurMap = {
    light: 'backdrop-blur-sm',
    medium: 'backdrop-blur-md',
    strong: 'backdrop-blur-lg'
  };

  return (
    <div
      className={cn(
        'rounded-tahoe-lg border border-white/10',
        'bg-white/10 dark:bg-black/20',
        blurMap[intensity],
        elevated && 'shadow-xl shadow-black/5',
        'transition-all duration-300',
        'hover:border-white/20 hover:shadow-2xl',
        className
      )}
    >
      {children}
    </div>
  );
}
```

#### Intrusive Alert Component

```typescript
// src/components/ui/IntrusiveAlert.tsx
import { AlertCircle, X } from 'lucide-react';
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface IntrusiveAlertProps {
  title: string;
  message: string;
  severity: 'critical' | 'risk' | 'info';
  onDismiss?: () => void;
  actionButton?: {
    label: string;
    onClick: () => void;
  };
}

export function IntrusiveAlert({
  title,
  message,
  severity,
  onDismiss,
  actionButton
}: IntrusiveAlertProps) {
  const [isVisible, setIsVisible] = useState(true);

  const severityStyles = {
    critical: 'bg-red-500/95 border-red-600/50',
    risk: 'bg-amber-500/95 border-amber-600/50',
    info: 'bg-blue-500/95 border-blue-600/50'
  };

  const handleDismiss = () => {
    setIsVisible(false);
    onDismiss?.();
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -100, opacity: 0 }}
          className="fixed top-4 left-1/2 -translate-x-1/2 z-50 w-full max-w-2xl"
        >
          <div
            className={cn(
              'rounded-tahoe-lg border p-6',
              'backdrop-blur-xl shadow-2xl',
              severityStyles[severity]
            )}
          >
            <div className="flex items-start gap-4">
              <AlertCircle className="h-6 w-6 text-white flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-white mb-2">
                  {title}
                </h3>
                <p className="text-white/90 text-sm leading-relaxed">
                  {message}
                </p>
                {actionButton && (
                  <button
                    onClick={actionButton.onClick}
                    className="mt-4 px-4 py-2 bg-white/20 hover:bg-white/30 rounded-tahoe text-white font-medium transition-colors"
                  >
                    {actionButton.label}
                  </button>
                )}
              </div>
              <button
                onClick={handleDismiss}
                className="text-white/70 hover:text-white transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
```

## Application Architecture

### Folder Structure

```
src/
├── components/
│   ├── ui/                    # Reusable UI components
│   │   ├── GlassCard.tsx
│   │   ├── IntrusiveAlert.tsx
│   │   ├── HealthBadge.tsx
│   │   └── LoadingState.tsx
│   ├── auth/                  # Authentication components
│   │   ├── GoogleAuth.tsx
│   │   └── ProtectedRoute.tsx
│   ├── dashboard/             # Dashboard-specific components
│   │   ├── PortfolioHealth.tsx
│   │   ├── ProjectCard.tsx
│   │   └── MetricChart.tsx
│   └── project/               # Project detail components
│       ├── ProjectHeader.tsx
│       ├── DeliveryTimeline.tsx
│       └── ActionQueue.tsx
├── pages/
│   ├── Dashboard.tsx          # Main dashboard view
│   ├── ProjectDetail.tsx      # Individual project view
│   └── ActionQueue.tsx        # Action items view
├── hooks/
│   ├── useSupabaseRealtime.ts # Real-time subscriptions
│   ├── useProjectHealth.ts    # Project health data
│   └── useAuth.ts             # Authentication state
├── lib/
│   ├── supabase.ts            # Supabase client
│   ├── auth.ts                # Auth helpers
│   └── utils.ts               # Utility functions
├── types/
│   └── database.ts            # TypeScript types from Supabase
└── styles/
    └── globals.css            # Global styles + Tailwind
```

### Google OAuth Implementation

```typescript
// src/lib/auth.ts
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
);

export async function signInWithGoogle() {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
      queryParams: {
        hd: 'oneorigin.us' // Restrict to domain
      }
    }
  });

  if (error) throw error;
  return data;
}

export async function checkAllowlist(email: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('user_allowlist')
    .select('is_active')
    .eq('email', email)
    .single();

  if (error || !data) return false;
  return data.is_active;
}

export async function signOut() {
  await supabase.auth.signOut();
}

// Auth state listener
export function onAuthStateChange(callback: (session: any) => void) {
  return supabase.auth.onAuthStateChange((_event, session) => {
    callback(session);
  });
}
```

```typescript
// src/components/auth/GoogleAuth.tsx
import { useState } from 'react';
import { signInWithGoogle } from '@/lib/auth';
import { Chrome } from 'lucide-react';

export function GoogleAuth() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSignIn = async () => {
    try {
      setIsLoading(true);
      setError(null);
      await signInWithGoogle();
    } catch (err) {
      setError('Failed to sign in. Please try again.');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <GlassCard className="p-8 w-full max-w-md">
        <div className="text-center">
          <h1 className="text-3xl font-bold mb-2">OneValue</h1>
          <p className="text-gray-600 mb-8">Delivery Intelligence Console</p>
          
          <button
            onClick={handleSignIn}
            disabled={isLoading}
            className={cn(
              'w-full flex items-center justify-center gap-3',
              'px-6 py-3 rounded-tahoe',
              'bg-white border border-gray-300',
              'hover:bg-gray-50 hover:border-gray-400',
              'transition-all duration-200',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            <Chrome className="h-5 w-5" />
            <span className="font-medium">
              {isLoading ? 'Signing in...' : 'Sign in with Google'}
            </span>
          </button>

          {error && (
            <p className="mt-4 text-sm text-red-600">{error}</p>
          )}

          <p className="mt-6 text-xs text-gray-500">
            Restricted to @oneorigin.us accounts only
          </p>
        </div>
      </GlassCard>
    </div>
  );
}
```

### Real-time Data Integration

```typescript
// src/hooks/useSupabaseRealtime.ts
import { useEffect, useState } from 'react';
import { supabase } from '@/lib/supabase';
import { RealtimeChannel } from '@supabase/supabase-js';

interface UseRealtimeOptions<T> {
  table: string;
  filter?: string;
  event?: 'INSERT' | 'UPDATE' | 'DELETE' | '*';
  onUpdate?: (payload: T) => void;
}

export function useSupabaseRealtime<T>({
  table,
  filter,
  event = '*',
  onUpdate
}: UseRealtimeOptions<T>) {
  const [data, setData] = useState<T[]>([]);
  const [channel, setChannel] = useState<RealtimeChannel | null>(null);

  useEffect(() => {
    const subscription = supabase
      .channel(`${table}-changes`)
      .on(
        'postgres_changes',
        { 
          event, 
          schema: 'public', 
          table,
          filter 
        },
        (payload) => {
          if (payload.eventType === 'INSERT') {
            setData(prev => [...prev, payload.new as T]);
          } else if (payload.eventType === 'UPDATE') {
            setData(prev => 
              prev.map(item => 
                (item as any).id === (payload.new as any).id 
                  ? payload.new as T 
                  : item
              )
            );
          } else if (payload.eventType === 'DELETE') {
            setData(prev => 
              prev.filter(item => (item as any).id !== (payload.old as any).id)
            );
          }
          
          onUpdate?.(payload.new as T);
        }
      )
      .subscribe();

    setChannel(subscription);

    return () => {
      subscription.unsubscribe();
    };
  }, [table, filter, event]);

  return { data, channel };
}
```

### Dashboard Implementation

```typescript
// src/pages/Dashboard.tsx
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/lib/supabase';
import { PortfolioHealth } from '@/components/dashboard/PortfolioHealth';
import { ProjectCard } from '@/components/dashboard/ProjectCard';
import { useSupabaseRealtime } from '@/hooks/useSupabaseRealtime';

interface Project {
  id: string;
  project_name: string;
  overall_health: 'Healthy' | 'At Risk' | 'Critical' | 'Unknown';
  blocker_count: number;
  renewal_risk_score: number;
}

export function Dashboard() {
  // Fetch initial data
  const { data: projects, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('project_health_metrics')
        .select(`
          *,
          sow_contracts (
            project_name,
            start_date,
            end_date
          )
        `)
        .order('overall_health', { ascending: true });

      if (error) throw error;
      return data;
    }
  });

  // Subscribe to real-time updates
  useSupabaseRealtime<Project>({
    table: 'project_health_metrics',
    event: '*',
    onUpdate: (payload) => {
      console.log('Project health updated:', payload);
      // React Query will automatically refetch
    }
  });

  if (isLoading) {
    return <LoadingState />;
  }

  const critical = projects?.filter(p => p.overall_health === 'Critical') || [];
  const atRisk = projects?.filter(p => p.overall_health === 'At Risk') || [];
  const healthy = projects?.filter(p => p.overall_health === 'Healthy') || [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 p-6">
      {/* Critical Alerts - Always Visible */}
      {critical.length > 0 && (
        <IntrusiveAlert
          title="Critical Projects Require Attention"
          message={`${critical.length} project(s) in critical state`}
          severity="critical"
          actionButton={{
            label: 'View Details',
            onClick: () => {
              // Navigate to first critical project
            }
          }}
        />
      )}

      {/* Portfolio Overview */}
      <PortfolioHealth
        total={projects?.length || 0}
        healthy={healthy.length}
        atRisk={atRisk.length}
        critical={critical.length}
      />

      {/* Project Grid */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Critical first */}
        {critical.map(project => (
          <ProjectCard key={project.id} project={project} priority="critical" />
        ))}
        
        {/* At Risk second */}
        {atRisk.map(project => (
          <ProjectCard key={project.id} project={project} priority="risk" />
        ))}
        
        {/* Healthy last */}
        {healthy.map(project => (
          <ProjectCard key={project.id} project={project} priority="healthy" />
        ))}
      </div>
    </div>
  );
}
```

### Project Card Component

```typescript
// src/components/dashboard/ProjectCard.tsx
import { HealthBadge } from '@/components/ui/HealthBadge';
import { AlertCircle, Calendar, TrendingUp } from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';

interface ProjectCardProps {
  project: {
    id: string;
    project_name: string;
    overall_health: string;
    blocker_count: number;
    renewal_risk_score: number;
    last_activity_date: string;
    sow_contracts: {
      end_date: string;
    };
  };
  priority: 'critical' | 'risk' | 'healthy';
}

export function ProjectCard({ project, priority }: ProjectCardProps) {
  const priorityBorder = {
    critical: 'border-red-500/50',
    risk: 'border-amber-500/50',
    healthy: 'border-green-500/50'
  };

  const daysUntilEnd = Math.ceil(
    (new Date(project.sow_contracts.end_date).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  );

  return (
    <GlassCard 
      className={cn('p-6 cursor-pointer', priorityBorder[priority])}
      elevated
    >
      <div className="flex items-start justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          {project.project_name}
        </h3>
        <HealthBadge health={project.overall_health} />
      </div>

      <div className="space-y-3">
        {/* Blockers */}
        {project.blocker_count > 0 && (
          <div className="flex items-center gap-2 text-sm">
            <AlertCircle className="h-4 w-4 text-red-500" />
            <span className="text-gray-700">
              {project.blocker_count} active blocker{project.blocker_count !== 1 ? 's' : ''}
            </span>
          </div>
        )}

        {/* Contract End Date */}
        <div className="flex items-center gap-2 text-sm">
          <Calendar className="h-4 w-4 text-gray-500" />
          <span className="text-gray-700">
            {daysUntilEnd > 0 ? `${daysUntilEnd} days remaining` : 'Contract expired'}
          </span>
        </div>

        {/* Renewal Risk */}
        {project.renewal_risk_score > 0.5 && (
          <div className="flex items-center gap-2 text-sm">
            <TrendingUp className="h-4 w-4 text-amber-500" />
            <span className="text-gray-700">
              {Math.round(project.renewal_risk_score * 100)}% renewal risk
            </span>
          </div>
        )}
      </div>

      {/* Last Activity */}
      <div className="mt-4 pt-4 border-t border-gray-200">
        <p className="text-xs text-gray-500">
          Last activity: {new Date(project.last_activity_date).toLocaleDateString()}
        </p>
      </div>
    </GlassCard>
  );
}
```

## Data Visualization

### Health Metrics Chart

```typescript
// src/components/dashboard/MetricChart.tsx
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { GlassCard } from '@/components/ui/GlassCard';

interface MetricChartProps {
  data: Array<{
    date: string;
    health_score: number;
  }>;
  projectName: string;
}

export function MetricChart({ data, projectName }: MetricChartProps) {
  return (
    <GlassCard className="p-6">
      <h3 className="text-lg font-semibold mb-4">Health Trend</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
          <XAxis 
            dataKey="date" 
            stroke="#6B7280"
            fontSize={12}
          />
          <YAxis 
            stroke="#6B7280"
            fontSize={12}
            domain={[0, 100]}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'rgba(255, 255, 255, 0.95)',
              border: '1px solid #E5E7EB',
              borderRadius: '12px',
              backdropFilter: 'blur(8px)'
            }}
          />
          <Line 
            type="monotone" 
            dataKey="health_score" 
            stroke="#3B82F6"
            strokeWidth={2}
            dot={{ fill: '#3B82F6', r: 4 }}
            activeDot={{ r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </GlassCard>
  );
}
```

## Loading & Error States

```typescript
// src/components/ui/LoadingState.tsx
export function LoadingState() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <GlassCard className="p-8">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
          <p className="text-gray-600">Loading delivery intelligence...</p>
        </div>
      </GlassCard>
    </div>
  );
}

// src/components/ui/ErrorState.tsx
export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <GlassCard className="p-8 max-w-md">
        <div className="text-center">
          <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold mb-2">Something went wrong</h3>
          <p className="text-gray-600 mb-4">{message}</p>
          {retry && (
            <button
              onClick={retry}
              className="px-4 py-2 bg-blue-500 text-white rounded-tahoe hover:bg-blue-600 transition-colors"
            >
              Try Again
            </button>
          )}
        </div>
      </GlassCard>
    </div>
  );
}
```

## Responsive Design

All components must be mobile-responsive:

```typescript
// Mobile-first approach
<div className="
  grid 
  grid-cols-1           /* Mobile: 1 column */
  md:grid-cols-2        /* Tablet: 2 columns */
  lg:grid-cols-3        /* Desktop: 3 columns */
  gap-4 
  md:gap-6              /* Larger gaps on bigger screens */
">
  {/* Content */}
</div>
```

## Performance Optimization

1. **Code Splitting**
```typescript
// Lazy load heavy components
const ProjectDetail = lazy(() => import('@/pages/ProjectDetail'));
```

2. **Memoization**
```typescript
const MemoizedProjectCard = memo(ProjectCard);
```

3. **Virtual Scrolling** for large lists
```typescript
import { useVirtualizer } from '@tanstack/react-virtual';
```

## Quality Checklist

Before marking any frontend task complete:

- [ ] Component follows Tahoe OS26 design system
- [ ] Responsive on mobile, tablet, desktop
- [ ] Loading states implemented
- [ ] Error states handled gracefully
- [ ] Accessibility: keyboard navigation works
- [ ] Accessibility: ARIA labels present
- [ ] Real-time updates working
- [ ] TypeScript types defined
- [ ] Performance optimized (< 2s load time)

## Next Steps

1. Read references/tahoe_design_system.md for complete design specs
2. Read references/component_patterns.md for React best practices
3. Test with scripts/generate_component.py for scaffolding
4. Coordinate with Backend Lead on API contracts